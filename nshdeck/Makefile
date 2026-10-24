#
PROG=	nshdeck
MAN=	nshdeck.8

.PATH:	${.CURDIR}/.. ${.CURDIR}/../nshd

.include "../nsh-version.mk"

.if ${NSH_RELEASE} != Yes
DEBUG?=-O0 -g
.endif

.if make(install)
PREFIX?=/usr/local
BINDIR?=${PREFIX}/sbin
MANDIR?=${PREFIX}/man/man
.endif

CFLAGS+=-Wmissing-prototypes -Wformat -Wall -Wbad-function-cast
CFLAGS+=-I${.CURDIR} -I${.CURDIR}/.. -I${.CURDIR}/../nshd

SRCS=	nshdeck.c front.c sessions.c
# nshd's log, and nsh's facts, which session reads
SRCS+=	log.c facts.c

LDADD=	-levent -lutil
DPADD=	${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
