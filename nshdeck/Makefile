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

SRCS=	nshdeck.c front.c sessions.c tables.c
# nshd's log, and nsh's facts, which session reads
SRCS+=	log.c facts.c
# nsh's completion, which session runs on nshd's tables
SRCS+=	complete.c makeargv.c genget.c stringlist.c

LDADD=	-levent -lutil
DPADD=	${LIBEVENT} ${LIBUTIL}

# the page, which httpd serves from its chroot
HTDOCS?=/var/www/htdocs/nshdeck

afterinstall:
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${HTDOCS}
	${INSTALL} -c -o root -g wheel -m 444 ${.CURDIR}/htdocs/index.html \
	    ${.CURDIR}/htdocs/app.js ${.CURDIR}/htdocs/ifdefs.js \
	    ${.CURDIR}/htdocs/inspector.js ${.CURDIR}/htdocs/style.css \
	    ${DESTDIR}${HTDOCS}

.include <bsd.prog.mk>
