# $nsh: Makefile,v 1.30 2008/02/14 01:00:59 chris Exp $
#
PROG= nsh

CFLAGS=-O -Wmissing-prototypes -Wformat -Wall -Wpointer-arith -Wbad-function-cast #-W

SRCS=arp.c compile.c main.c genget.c commands.c stats.c routesys.c
SRCS+=ctl.c show.c if.c version.c route.c conf.c complete.c ieee80211.c
SRCS+=bridge.c tunnel.c media.c sysctl.c wi.c passwd.c pfsync.c carp.c
SRCS+=trunk.c who.c timeslot.c more.c stringlist.c makeargv.c
CLEANFILES+=compile.c
LDADD=-ledit -ltermcap #-static

NOMAN=1

compile.c: compile.sh
	sh compile.sh

.include <bsd.prog.mk>
