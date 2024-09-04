#
PROG= bgpnsh

.PATH:${.CURDIR}/..

.include "../nsh-version.mk"

.if ${NSH_RELEASE} != Yes
DEBUG?=-O0 -g
.endif

.if make(install)
PREFIX?=/usr/local
BINDIR?=${PREFIX}/bin
MANDIR?=${PREFIX}/man/man
.endif

CFLAGS+=-Wmissing-prototypes -Wformat -Wall -Wbad-function-cast
CPPFLAGS+=-DNSH_VERSION=${NSH_VERSION}

SRCS=bgpnsh.c compile.c bgpcommands.c complete.c genget.c more.c \
	stringlist.c utf8.c stubs.c cmdargs.c ctlargs.c prompt.c \
	helpcommands.c makeargv.c
CLEANFILES+=compile.c
LDADD=-lutil -ledit -ltermcap

.if make(static)
LDADD+=-static
.endif

static: all

MAN=bgpnsh.8

compile.c: compile.sh
	sh ${.CURDIR}/../compile.sh

.include <bsd.prog.mk>
