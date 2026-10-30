#
PROG= nsh

.PATH:	${.CURDIR}/../lib

.include "../nsh-version.mk"

.if ${NSH_RELEASE} != Yes
DEBUG?=-O0 -g
.endif


.if make(install)
PREFIX?=/usr/local
BINDIR?=${PREFIX}/bin
MANDIR?=${PREFIX}/man/man
.endif

# For use with flashrd:
#CFLAGS=-O -DDHCPLEASES=\"/flash/dhcpd.leases\" -Wmissing-prototypes -Wformat -Wall -Wpointer-arith -Wbad-function-cast #-W
CFLAGS?=-O
CFLAGS+=-Wmissing-prototypes -Wformat -Wall -Wbad-function-cast -I/usr/local/include #-W -Wpointer-arith
CFLAGS+=-I${.CURDIR}/../lib
CPPFLAGS+=-DNSH_VERSION=${NSH_VERSION}

SRCS=main.c loop.c compile.c mantab.c client.c nshcmds.c tables.c complete.c
SRCS+=editing.c makeargv.c genget.c stringlist.c prompt.c more.c facts.c
SRCS+=showfacts.c renderif.c renderrt.c rendersys.c version.c cmdargs.c
SRCS+=ctlargs.c bgpcommands.c helpcommands.c utils.c hashtable.c utf8.c
CLEANFILES+=compile.c mantab.c

LDADD=-lutil -ledit -ltermcap

.if make(static)
LDADD+=-static
.endif

MAN=nsh.8

static: all

compile.c: compile.sh *.c *.h
	sh ${.CURDIR}/../lib/compile.sh

mantab.c: mantab.sh nsh.8
	sh ${.CURDIR}/mantab.sh ${.CURDIR}/nsh.8 > mantab.c

.include <bsd.prog.mk>
