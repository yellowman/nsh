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
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${HTDOCS} \
	    ${DESTDIR}${HTDOCS}/xterm
	${INSTALL} -c -o root -g wheel -m 444 ${.CURDIR}/htdocs/index.html \
	    ${.CURDIR}/htdocs/app.js ${.CURDIR}/htdocs/registry.js \
	    ${.CURDIR}/htdocs/inspector.js ${.CURDIR}/htdocs/daemons.js \
	    ${.CURDIR}/htdocs/pfconf.js ${.CURDIR}/htdocs/bgpdconf.js \
	    ${.CURDIR}/htdocs/editors.js ${.CURDIR}/htdocs/relations.js \
	    ${.CURDIR}/htdocs/sheets.js ${.CURDIR}/htdocs/term.js \
	    ${.CURDIR}/htdocs/style.css ${DESTDIR}${HTDOCS}
	${INSTALL} -c -o root -g wheel -m 444 \
	    ${.CURDIR}/htdocs/xterm/xterm.js ${.CURDIR}/htdocs/xterm/xterm.css \
	    ${.CURDIR}/htdocs/xterm/addon-fit.js \
	    ${.CURDIR}/htdocs/xterm/LICENSE \
	    ${.CURDIR}/htdocs/xterm/LICENSE.addon-fit \
	    ${DESTDIR}${HTDOCS}/xterm

.include <bsd.prog.mk>
