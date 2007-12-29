# $nsh: Makefile,v 1.23 2007/12/29 23:11:22 chris Exp $
#
PROG= nsh

CFLAGS=-g -Wmissing-prototypes -Wformat -Wall -Wpointer-arith -Wbad-function-cast -W

SRCS=compile.c main.c genget.c commands.c stats.c mbuf.c routesys.c
SRCS+=show.c if.c version.c route.c conf.c editing.c ieee80211.c
SRCS+=bridge.c tunnel.c media.c sysctl.c wi.c passwd.c pfsync.c carp.c
SRCS+=trunk.c who.c timeslot.c
CLEANFILES+=compile.c
LDADD=-ledit -ltermcap -lutil #-static

NOMAN=1

compile.c: compile.sh
	sh compile.sh

.include <bsd.prog.mk>
