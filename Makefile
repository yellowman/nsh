# $nsh: Makefile,v 1.19 2007/12/26 03:55:49 chris Exp $
#
PROG= nsh

CFLAGS=-g -Wmissing-prototypes -Wformat -Wall -Wpointer-arith #-W -Wbad-function-cast -Wtraditional

SRCS=compile.c main.c genget.c commands.c kread.c stats.c mbuf.c routesys.c
SRCS+=show.c if.c version.c route.c conf.c editing.c ieee80211.c
SRCS+=bridge.c tunnel.c media.c sysctl.c wi.c passwd.c pfsync.c carp.c
SRCS+=trunk.c
CLEANFILES+=compile.c
LDADD=-lkvm -ledit -ltermcap -lutil #-static

NOMAN=1

compile.c: compile.sh
	sh compile.sh

.include <bsd.prog.mk>
