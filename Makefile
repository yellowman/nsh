PROG= nsh

CFLAGS+=-g

SRCS=compile.c main.c genget.c commands.c kread.c stats.c mbuf.c routemsg.c
SRCS+=routepr.c rate.c if.c version.c
CLEANFILES+=compile.c
LDADD=-lkvm

NOMAN=1

compile.c: compile.sh
	sh compile.sh

.include <bsd.prog.mk>
