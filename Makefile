#
PROG= nsh

SUBDIR += bgpnsh nshd nshdeck

.PATH:	${.CURDIR}/lib

.PHONY: release dist

.include "nsh-version.mk"

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
CFLAGS+=-I${.CURDIR} -I${.CURDIR}/lib
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

# convenience target for producing statically linked binaries
static: $(PROG)
	${MAKE} -C ${.CURDIR}/bgpnsh static
	${MAKE} -C ${.CURDIR}/nshd static

compile.c: compile.sh *.c *.h
	sh ${.CURDIR}/compile.sh

mantab.c: mantab.sh nsh.8
	sh ${.CURDIR}/mantab.sh ${.CURDIR}/nsh.8 > mantab.c

release: clean
	sed -i -e "s/_RELEASE=No/_RELEASE=Yes/" ${.CURDIR}/nsh-version.mk
	${MAKE} -C ${.CURDIR} dist
	sed -i -e "s/_RELEASE=Yes/_RELEASE=No/" ${.CURDIR}/nsh-version.mk

dist: clean
	mkdir /tmp/nsh-${NSH_VERSION}
	(cd ${.CURDIR} && pax -rw * /tmp/nsh-${NSH_VERSION})
	find /tmp/nsh-${NSH_VERSION} -name obj -type d -delete
	rm /tmp/nsh-${NSH_VERSION}/nsh-dist.txt
	tar -C /tmp -zcf ${.CURDIR}/nsh-${NSH_VERSION}.tar.gz nsh-${NSH_VERSION}
	rm -rf /tmp/nsh-${NSH_VERSION}
	tar -ztf ${.CURDIR}/nsh-${NSH_VERSION}.tar.gz | \
		sed -e 's/^nsh-${NSH_VERSION}//' | \
		sort > ${.CURDIR}/nsh-dist.txt.new
	diff -u ${.CURDIR}/nsh-dist.txt ${.CURDIR}/nsh-dist.txt.new
	rm ${.CURDIR}/nsh-dist.txt.new

.include <bsd.prog.mk>
.include <bsd.subdir.mk>
