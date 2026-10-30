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
#	perl scripts/kernscan.pl /usr/src "OpenBSD 7.8" > nshd/kernel.c
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
# but the cloners' and the files of the ioctl functions their handlers
# call takes them, so an interface no cloner made takes none.
#
# @limits are values the kernel checks or reports that no header
# userland includes defines, each read from the one #define it has.

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
    SIOCSETPFSYNC SIOCSTRUNK SIOCSTRUNKPORT SIOCSTRUNKDELPORT SIOCSWG
    SIOCSSPPPPARAMS PPPOESETPARMS SIOCBRDGADD SIOCBRDGDEL SIOCBRDGADDS
    SIOCBRDGDELS SIOCBRDGGIFFLGS SIOCBRDGSIFFLGS SIOCBRDGSCACHE SIOCBRDGSTO
    SIOCBRDGSPRI SIOCBRDGSHT SIOCBRDGSFD SIOCBRDGSMA SIOCBRDGSIFPRIO
    SIOCBRDGSIFCOST SIOCBRDGSADDR SIOCBRDGDADDR SIOCBRDGARL SIOCBRDGSIFPROT);
my %drv = map { $_ => 1 } @drv;

# Values the kernel checks or reports that no header userland includes
# defines: kernel.c's name for each, and the file and macro it is read
# from, or the file, a pattern in its code and what the pattern finds
my @limits = (
	[ 'kern_txpower_min', 'net80211/ieee80211_var.h',
	    'IEEE80211_TXPOWER_MIN' ],
	[ 'kern_txpower_max', 'net80211/ieee80211_var.h',
	    'IEEE80211_TXPOWER_MAX' ],
	[ 'kern_bstp_port_admcost', 'net/if_bridge.h', 'BSTP_PORT_ADMCOST' ],
	[ 'kern_bstp_max_path_cost', 'net/bridgestp.c', 'BSTP_MAX_PATH_COST' ],
	[ 'kern_bstp_max_priority', 'net/bridgestp.c', 'BSTP_MAX_PRIORITY' ],
	[ 'kern_bstp_max_port_priority', 'net/bridgestp.c',
	    'BSTP_MAX_PORT_PRIORITY' ],
	[ 'kern_bstp_tick_val', 'net/bridgestp.c', 'BSTP_TICK_VAL' ],
	[ 'kern_bstp_min_hello_time', 'net/bridgestp.c',
	    'BSTP_MIN_HELLO_TIME' ],
	[ 'kern_bstp_max_hello_time', 'net/bridgestp.c',
	    'BSTP_MAX_HELLO_TIME' ],
	[ 'kern_bstp_min_fwd_delay', 'net/bridgestp.c',
	    'BSTP_MIN_FORWARD_DELAY' ],
	[ 'kern_bstp_max_fwd_delay', 'net/bridgestp.c',
	    'BSTP_MAX_FORWARD_DELAY' ],
	[ 'kern_bstp_min_max_age', 'net/bridgestp.c', 'BSTP_MIN_MAX_AGE' ],
	[ 'kern_bstp_max_max_age', 'net/bridgestp.c', 'BSTP_MAX_MAX_AGE' ],
	[ 'kern_bstp_priority_step', 'net/bridgestp.c',
	    case_finds('SIOCBRDGSPRI', 'val -= val % (\d+);'),
	    'what SIOCBRDGSPRI rounds down to' ],
	[ 'kern_bstp_port_priority_step', 'net/bridgestp.c',
	    case_finds('SIOCBRDGSIFPRIO', 'val -= val % (\d+);'),
	    'what SIOCBRDGSIFPRIO rounds down to' ],
	[ 'kern_bstp_protover', 'net/bridgestp.c',
	    qr/\bbs->bs_protover = (BSTP_PROTO_\w+);/,
	    'the protocol bstp_create() sets' ],
	[ 'kern_bstp_ht_protover', 'net/bridgestp.c',
	    case_finds('SIOCBRDGSHT', 'bs->bs_protover != (BSTP_PROTO_\w+)'),
	    'the only protocol SIOCBRDGSHT takes' ],
);

@ARGV == 2 or die "usage: kernscan.pl srcdir label\n";
my ($src, $label) = @ARGV;

my @lines;		# kernel.c's line for each limit
foreach my $l (@limits) {
	my ($name, $file, $what, $about) = @$l;
	my $v;
	if (ref $what) {
		($v) = slurp("$src/sys/$file") =~ $what
		    or die "$name: $about: not in $file\n";
	} else {
		open(my $fh, '<', "$src/sys/$file")
		    or die "$src/sys/$file: $!\n";
		my $text = join('', <$fh>);
		close($fh);
		# "-50", "0x0008" or "(6 * 256)"
		my ($n, $times) = $text =~ /^\#define\s+$what\s+
		    \(?(-?\d+|0x[0-9a-fA-F]+)(?:\s*\*\s*(\d+))?\)?\s/mx
		    or die "$what: not a number in $file\n";
		$v = defined $times ? $n * $times : $n;
		$about = $what;
	}
	push @lines, "const int $name = $v;\t/* $about */\n";
}
my @dirs = map { "$src/sys/$_" } qw(net netinet netinet6 netmpls);

my %body;		# function name => its body, by file
my %global;		# function name => its body, from any of @dirs
my %where;		# function name => its file, from any of @dirs
my %reached;		# ioctl functions in other files the cloners reach
my @cloners;		# [ name, create function, file ]

foreach my $dir (@dirs) {
	opendir(my $dh, $dir) or die "$dir: $!\n";
	foreach my $f (sort grep { /\.c$/ } readdir($dh)) {
		my $text = slurp("$dir/$f");
		my $fns = functions($text);
		$global{$_} = $fns->{$_} foreach keys %$fns;
		$where{$_} = $f foreach keys %$fns;
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
		$reached{$fn} = 1 unless defined $fns->{$fn};
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
drv_only_cloners([ map { $_->[2] } @cloners ], [ sort keys %reached ]);

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
#include <netinet/if_ether.h>
#include <net/if_pflow.h>
#include <net/if_trunk.h>
#include <net/if_wg.h>
#include <net/ppp_defs.h>
#include <net/if_sppp.h>
#include <net/if_pppoe.h>
#include <net/if_bridge.h>
#include "kernel.h"

const char kernel_source[] = "$label";

EOF
print @lines, "\n";
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

# Only the cloners' files may take the ioctls in @drv, and the file of
# an ioctl function their handlers call (if_spppsubr.c for pppoe) when
# no other file calls it. net/if.c may only hand them on to the driver:
# ifioctl()'s case for them falls to its default, pru_control() and
# then if_ioctl. Anything else in sys, a hardware driver say, stops the
# scan.
sub drv_only_cloners {
	my ($cloners, $reached) = @_;
	my %ok = map { $_ => 1 } @$cloners;
	my (@files, @taken, %called);

	-d "$src/sys/dev" or die "$src/sys/dev: no hardware drivers to check\n";
	find_c("$src/sys", \@files);
	foreach my $path (@files) {
		my $text = slurp($path);
		my ($f) = $path =~ m{([^/]+)$};
		foreach my $fn (@$reached) {
			$called{$fn} = 1 if !$ok{$f} && $f ne $where{$fn} &&
			    $text =~ /\b$fn\s*\(/;
		}
		foreach my $i (@drv) {
			next unless $text =~ /\bcase\s+$i\s*:/;
			push @taken, [ $i, $path, $f ];
			next unless $path =~ m{/sys/net/if\.c$};
			$text =~ /\bcase\s+$i\s*:(\s*case\s+\w+\s*:)*\s*
			    if\s*\(\(error\s*=\s*suser\(p\)\)\s*!=\s*0\)\s*
			    break;\s*default:\s*error\s*=\s*pru_control\(/x or
			    die "net/if.c does more with $i than hand it on\n";
		}
	}
	$ok{$where{$_}} = 1 foreach grep { !$called{$_} } @$reached;
	foreach my $t (@taken) {
		my ($i, $path, $f) = @$t;
		next if $ok{$f} && $path =~ m{/sys/net(inet6?|mpls)?/};
		die "$i is taken in $path, which no cloner is\n"
		    unless $path =~ m{/sys/net/if\.c$};
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
# A pattern for what one case of a switch says before the next case: the
# code of "case $label:", up to and with $what, which captures a value
sub case_finds {
	my ($label, $what) = @_;
	return qr/\bcase\s+$label:(?:(?!\bcase\b|\bdefault\b).)*?$what/s;
}

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
