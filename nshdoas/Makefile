#
PROG= nshdoas

.PATH:${.CURDIR}/..

.include "../nsh-version.mk"

.if ${NSH_RELEASE} != Yes
DEBUG?=-O0 -g
.endif

.if make(install)
PREFIX?=/usr/local
BINDIR?=${PREFIX}/libexec
MANDIR?=${PREFIX}/man/man
.endif

CFLAGS+=-Wmissing-prototypes -Wformat -Wall -Wbad-function-cast
CPPFLAGS+=-DNSH_VERSION=${NSH_VERSION}
CPPFLAGS+=-I${.CURDIR}/.. -I ${.CURDIR}

SRCS=parse.y nshdoas.c env.c
LDADD=-lutil

.if make(static)
LDADD+=-static
.endif

BINOWN= root
BINMODE=4555

YFLAGS=

NOMAN=yes

static: all

.include <bsd.prog.mk>
