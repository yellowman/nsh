PROG= nsh

CFLAGS+=-g

SRCS= main.c genget.c commands.c route.c kread.c stats.c
LDADD= -lkvm

NOMAN=1

.include <bsd.prog.mk>
