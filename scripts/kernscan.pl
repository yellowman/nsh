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
# cloners make and which driver ioctls they take, from the kernel source
#
#	perl scripts/kernscan.pl /usr/src "OpenBSD 7.8" > kernel.c
#
# For each cloner (IF_CLONE_INITIALIZER), the create function and the
# functions it calls in the same file are read for the if_flags and
# if_type they set, and the if_ioctl handler they install is read for
# SIOCBRDGRTS, which is_bridge() asks, and for the ioctls in @drv. The
# scanner stops rather than guess: a cloner whose create path sets
# if_flags or if_type more than one way must be listed in %choose, and a
# choice must still be one of the ways the source has.
#
# The ioctls in @drv are nsh's commands that only some drivers take.
# ifioctl() hands them to the driver, and a driver without a case for
# one answers ENOTTY. The scanner checks that, and that no file in sys
# but the cloners' takes them, so an interface no cloner made takes none.

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

my @drv = qw(SIOCSLIFPHYADDR SIOCDIFPHYADDR SIOCSLIFPHYRTABLE
    SIOCSLIFPHYTTL SIOCSLIFPHYDF SIOCSLIFPHYECN SIOCSVNETID SIOCDVNETID
    SIOCSVNETFLOWID SIOCSIFPARENT SIOCDIFPARENT SIOCSIFPAIR SIOCSETKALIVE
    SIOCSTXHPRIO SIOCSRXHPRIO SIOCSETLABEL SIOCDELLABEL SIOCSPWE3CTRLWORD
    SIOCSPWE3FAT SIOCSPWE3NEIGHBOR SIOCDPWE3NEIGHBOR SIOCSETPFLOW SIOCSVH
    SIOCSETPFSYNC);
my %drv = map { $_ => 1 } @drv;

@ARGV == 2 or die "usage: kernscan.pl srcdir label\n";
my ($src, $label) = @ARGV;
my @dirs = map { "$src/sys/$_" } qw(net netinet netinet6 netmpls);

my %body;		# function name => its body, by file
my %global;		# function name => its body, from any of @dirs
my @cloners;		# [ name, create function, file ]

foreach my $dir (@dirs) {
	opendir(my $dh, $dir) or die "$dir: $!\n";
	foreach my $f (sort grep { /\.c$/ } readdir($dh)) {
		my $text = slurp("$dir/$f");
		my $fns = functions($text);
		$global{$_} = $fns->{$_} foreach keys %$fns;
		next unless $text =~ /IF_CLONE_INITIALIZER\s*\(\s*"/;
		$body{$f} = $fns;
		while ($text =~ /IF_CLONE_INITIALIZER\s*\(\s*"(\w+)"\s*,\s*
		    (\w+)\s*,/gx) {
			push @cloners, [ $1, $2, $f ];
		}
	}
	closedir($dh);
}
die "no cloners in $src/sys\n" unless @cloners;
drv_only_cloners(map { $_->[2] } @cloners);

my (@rows, @arrays);
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

	# the driver ioctls its handler, or what that calls, has a case for
	my %takes;
	foreach my $fn (reach($fns, $ioctl, 1)) {
		my $b = defined $fns->{$fn} ? $fns->{$fn} : $global{$fn};
		while ($b =~ /\bcase\s+(\w+)\s*:/g) {
			$takes{$1} = 1 if $drv{$1};
		}
	}
	my @takes = grep { $takes{$_} } @drv;
	push @arrays, sprintf("static const u_long %s_ioctls[] = {\n%s\t0\n};\n",
	    $name, join('', map { "\t$_,\n" } @takes));

	push @rows, sprintf("\t{ \"%s\", %s, %d,\n\t    %s,\n\t    %s_ioctls },\n",
	    $name, $type eq '' ? '0' : $type, $bridge,
	    join(' | ', sort keys %flags) || '0', $name);
}
foreach my $k (sort keys %choose) {
	die "%choose has $k, which is no cloner's\n" unless $used{$k};
}

print <<"EOF";
/*
 * What the kernel's interface cloners make: the if_type and if_flags
 * each create function sets, whether is_bridge() calls it a bridge, and
 * which of nsh's driver ioctls it takes.
 * Made by scripts/kernscan.pl; do not edit. From:
 *	$label
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <net/if_pflow.h>
#include "kernel.h"

const char kernel_source[] = "$label";

EOF
print join("\n", @arrays), "\n";
print "const struct kcloner kcloners[] = {\n";
print @rows;
print "\t{ NULL, 0, 0, 0, NULL }\n};\n";

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

# The functions fn calls, in the same file, and fn itself. With ioctls,
# also the ioctl functions it calls in other files, which take what the
# driver hands on.
sub reach {
	my ($fns, $fn, $ioctls) = @_;
	my %seen = ($fn => 1);
	my @todo = ($fn);

	while (my $f = shift @todo) {
		my $b = defined $fns->{$f} ? $fns->{$f} : $global{$f};
		while ($b =~ /\b(\w+)\s*\(/g) {
			my $c = $1;
			next if $seen{$c};
			next unless defined $fns->{$c} ||
			    ($ioctls && $c =~ /ioctl/ && defined $global{$c});
			$seen{$c} = 1;
			push @todo, $c;
		}
	}
	return sort keys %seen;
}

# Only the cloners' files may take the ioctls in @drv, and net/if.c may
# only hand them on to the driver: ifioctl()'s case for them falls to
# its default, pru_control() and then if_ioctl. Anything else in sys, a
# hardware driver say, stops the scan.
sub drv_only_cloners {
	my %ok = map { $_ => 1 } @_;
	my @files;

	-d "$src/sys/dev" or die "$src/sys/dev: no hardware drivers to check\n";
	find_c("$src/sys", \@files);
	foreach my $path (@files) {
		my $text = slurp($path);
		my ($f) = $path =~ m{([^/]+)$};
		foreach my $i (@drv) {
			next unless $text =~ /\bcase\s+$i\s*:/;
			next if $ok{$f} && $path =~ m{/sys/net(inet6?|mpls)?/};
			die "$i is taken in $path, which no cloner is\n"
			    unless $path =~ m{/sys/net/if\.c$};
			$text =~ /\bcase\s+$i\s*:(\s*case\s+\w+\s*:)*\s*
			    if\s*\(\(error\s*=\s*suser\(p\)\)\s*!=\s*0\)\s*
			    break;\s*default:\s*error\s*=\s*pru_control\(/x or
			    die "net/if.c does more with $i than hand it on\n";
		}
	}
}

sub find_c {
	my ($dir, $files) = @_;
	opendir(my $dh, $dir) or die "$dir: $!\n";
	foreach my $e (sort readdir($dh)) {
		next if $e =~ /^\./;
		if (-d "$dir/$e" && ! -l "$dir/$e") {
			find_c("$dir/$e", $files);
		} elsif ($e =~ /\.c$/) {
			push @$files, "$dir/$e";
		}
	}
	closedir($dh);
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
