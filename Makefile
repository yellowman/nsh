PROG= nsh

CFLAGS=-g -Wmissing-prototypes -Wformat # -Wall -W -Wtraditional -Wpointer-arith -Wbad-function-cast

SRCS=compile.c main.c genget.c commands.c kread.c stats.c mbuf.c routesys.c
SRCS+=routepr.c rate.c if.c version.c route.c conf.c editing.c ieee80211.c
SRCS+=bridge.c tunnel.c media.c
CLEANFILES+=compile.c
LDADD=-lkvm -ledit -ltermcap

NOMAN=1

compile.c: compile.sh
	sh compile.sh

.include <bsd.prog.mk>
