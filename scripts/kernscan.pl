#!/usr/bin/perl
#
# Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# kernscan.pl: write kernel.c, the table of what the kernel's interface
# cloners make, from the kernel source
#
#	perl scripts/kernscan.pl /usr/src "OpenBSD 7.8" > kernel.c
#
# For each cloner (IF_CLONE_INITIALIZER), the create function and the
# functions it calls in the same file are read for the if_flags and
# if_type they set, and the if_ioctl handler they install is read for
# SIOCBRDGRTS, which is_bridge() asks. The scanner stops rather than
# guess: a cloner whose create path sets if_flags or if_type more than
# one way must be listed in %choose, and a choice must still be one of
# the ways the source has.

use strict;
use warnings;

# Flags that say what an interface is doing, not what it is
my %runtime = map { $_ => 1 } qw(IFF_UP IFF_RUNNING IFF_OACTIVE
    IFF_PROMISC IFF_ALLMULTI);

# Cloners whose create path sets if_flags or if_type more than one way:
# the value it has when the create function returns. tun and tap share
# tun_create(), which branches on which of them called it, and
# carp_clone_create() sets if_type after ether_ifattach() has.
my %choose = (
	'carp if_type'	=> 'IFT_CARP',
	'tun if_flags'	=> 'IFF_POINTOPOINT|IFF_MULTICAST',
	'tun if_type'	=> 'IFT_TUNNEL',
	'tap if_flags'	=> 'IFF_BROADCAST|IFF_SIMPLEX|IFF_MULTICAST',
	'tap if_type'	=> 'IFT_ETHER',
);
my %used;

# Set by functions in other files, which this scanner does not follow
my %attach = (
	ether_ifattach	=> 'IFT_ETHER',
);

@ARGV == 2 or die "usage: kernscan.pl srcdir label\n";
my ($src, $label) = @ARGV;
my @dirs = map { "$src/sys/$_" } qw(net netinet netinet6 netmpls);

my %body;		# function name => its body, by file
my @cloners;		# [ name, create function, file ]

foreach my $dir (@dirs) {
	opendir(my $dh, $dir) or die "$dir: $!\n";
	foreach my $f (sort grep { /\.c$/ } readdir($dh)) {
		my $text = slurp("$dir/$f");
		next unless $text =~ /IF_CLONE_INITIALIZER\s*\(\s*"/;
		$body{$f} = functions($text);
		while ($text =~ /IF_CLONE_INITIALIZER\s*\(\s*"(\w+)"\s*,\s*
		    (\w+)\s*,/gx) {
			push @cloners, [ $1, $2, $f ];
		}
	}
	closedir($dh);
}
die "no cloners in $src/sys\n" unless @cloners;

my @rows;
foreach my $c (sort { $a->[0] cmp $b->[0] } @cloners) {
	my ($name, $create, $f) = @$c;
	my $fns = $body{$f};
	defined $fns->{$create} or die "$name: no $create in $f\n";

	my (%flags, %set, %types, %ioctls);
	foreach my $fn (reach($fns, $create)) {
		my $b = $fns->{$fn};
		while ($b =~ /(?:->|\.)if_flags\s*(=|\|=|&=)\s*([^;]*);/g) {
			my ($op, $v) = ($1, $2);
			my @v = $v =~ /\b(IFF_\w+)\b/g;
			if ($op eq '=') {
				$set{join('|', @v)} = 1;
			} elsif ($op eq '|=') {
				$flags{$_} = 1 foreach grep { !$runtime{$_} } @v;
			} elsif (grep { !$runtime{$_} } @v) {
				die "$name: $fn clears if_flags: $v\n";
			}
		}
		$types{$1} = 1 while $b =~ /(?:->|\.)if_type\s*=\s*(IFT_\w+)\s*;/g;
		$ioctls{$1} = 1 while $b =~ /(?:->|\.)if_ioctl\s*=\s*(\w+)\s*;/g;
		foreach my $a (keys %attach) {
			$types{$attach{$a}} = 1 if $b =~ /\b$a\s*\(/;
		}
	}
	my $set = pick($name, 'if_flags', \%set);
	$flags{$_} = 1 foreach grep { $_ ne '' } split(/\|/, $set);
	my $type = pick($name, 'if_type', \%types);
	keys(%ioctls) == 1 or die "$name: if_ioctl set ",
	    scalar(keys %ioctls), " ways\n";
	my ($ioctl) = keys %ioctls;
	defined $fns->{$ioctl} or die "$name: no $ioctl in $f\n";
	my $bridge = ($type eq 'IFT_BRIDGE' ||
	    $fns->{$ioctl} =~ /\bcase\s+SIOCBRDGRTS\s*:/) ? 1 : 0;

	push @rows, sprintf("\t{ \"%s\", %s, %d,\n\t    %s },\n", $name,
	    $type eq '' ? '0' : $type, $bridge,
	    join(' | ', sort keys %flags) || '0');
}
foreach my $k (sort keys %choose) {
	die "%choose has $k, which is no cloner's\n" unless $used{$k};
}

print <<"EOF";
/*
 * What the kernel's interface cloners make: the if_type and if_flags
 * each create function sets, and whether is_bridge() calls it a bridge.
 * Made by scripts/kernscan.pl; do not edit. From:
 *	$label
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include "kernel.h"

const char kernel_source[] = "$label";

const struct kcloner kcloners[] = {
EOF
print @rows;
print "\t{ NULL, 0, 0, 0 }\n};\n";

# The one value a cloner's create path sets, or the one %choose names
sub pick {
	my ($name, $what, $ways) = @_;
	my $key = "$name $what";
	my @w = sort keys %$ways;

	if (exists $choose{$key}) {
		die "$key: one way in the source now, take it out of %choose\n"
		    if @w <= 1;
		die "$key: \"$choose{$key}\" is not in the source: @w\n"
		    unless grep { $_ eq $choose{$key} } @w;
		$used{$key} = 1;
		return $choose{$key};
	}
	die "$key set ", scalar(@w), " ways: @w\n" if @w > 1;
	return @w ? $w[0] : '';
}

# The functions fn calls, in the same file, and fn itself
sub reach {
	my ($fns, $fn) = @_;
	my %seen = ($fn => 1);
	my @todo = ($fn);

	while (my $f = shift @todo) {
		while ($fns->{$f} =~ /\b(\w+)\s*\(/g) {
			next if $seen{$1} || !defined $fns->{$1};
			$seen{$1} = 1;
			push @todo, $1;
		}
	}
	return sort keys %seen;
}

# The functions in a file: a name at the start of a line, its
# parameters, and a body in braces
sub functions {
	my ($text) = @_;
	my %fns;

	while ($text =~ /^(\w+)\s*\([^;{]*?\)\s*\{/mg) {
		my ($name, $start, $depth) = ($1, pos($text) - 1, 0);
		my $i;
		for ($i = $start; $i < length($text); $i++) {
			my $ch = substr($text, $i, 1);
			$depth++ if $ch eq '{';
			last if $ch eq '}' && --$depth == 0;
		}
		die "$name: no end\n" if $i >= length($text);
		$fns{$name} = substr($text, $start, $i - $start + 1);
		pos($text) = $i + 1;
	}
	return \%fns;
}

# A file without its comments and preprocessor lines
sub slurp {
	my ($path) = @_;
	open(my $fh, '<', $path) or die "$path: $!\n";
	local $/;
	my $text = <$fh>;
	close($fh);
	$text =~ s{/\*.*?\*/}{ }gs;
	$text =~ s{//[^\n]*}{}g;
	$text =~ s{^\s*#(?:[^\n]*\\\n)*[^\n]*}{}mg;
	return $text;
}
