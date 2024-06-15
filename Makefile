#
PROG= nsh

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
CFLAGS+=-Wmissing-prototypes -Wformat -Wall -Wbad-function-cast -I/usr/local/include -Wno-error -Wno-unused-variable -Wno-implicit-function-declaration -Wno-pointer-sign -Wbad-function-cast -o ${.TARGET} #-W -Wpointer-arith
CPPFLAGS+=-DNSH_VERSION=${NSH_VERSION}

OSNAME != uname
.if $(OSNAME) == "OpenBSD"
# bgpnsh and nshdoas needs some porting work, eg: sudo?
# unveil() also is OpenBSD specific
SUBDIR += openbsd/bgpnsh openbsd/nshdoas

SRCS=openbsd/arp.c openbsd/compile.c openbsd/main.c openbsd/genget.c openbsd/commands.c openbsd/bgpcommands.c openbsd/stats.c openbsd/kroute.c
SRCS+=openbsd/ctl.c openbsd/show.c openbsd/if.c openbsd/version.c openbsd/route.c openbsd/conf.c openbsd/complete.c openbsd/ieee80211.c
SRCS+=openbsd/bridge.c openbsd/tunnel.c openbsd/media.c openbsd/sysctl.c openbsd/passwd.c openbsd/pfsync.c openbsd/carp.c
SRCS+=openbsd/trunk.c openbsd/who.c openbsd/more.c openbsd/stringlist.c openbsd/utils.c openbsd/sqlite3.c openbsd/ppp.c openbsd/prompt.c
SRCS+=openbsd/nopt.c openbsd/pflow.c openbsd/wg.c openbsd/nameserver.c openbsd/ndp.c openbsd/umb.c openbsd/utf8.c openbsd/cmdargs.c openbsd/ctlargs.c
SRCS+=openbsd/helpcommands.c openbsd/makeargv.c openbsd/hashtable.c openbsd/mantab.c
CLEANFILES+=openbsd/compile.c openbsd/mantab.c
LDADD=-lutil -ledit -ltermcap -lsqlite3 -L/usr/local/lib #-static

openbsd/compile.c: openbsd/compile.sh *.c *.h
	cd openbsd; sh ${.CURDIR}/openbsd/compile.sh

openbsd/mantab.c: openbsd/mantab.sh nsh.8
	cd openbsd; sh ${.CURDIR}/openbsd/mantab.sh ${.CURDIR}/nsh.8 > mantab.c
.endif

.if $(OSNAME) == "NetBSD"
SRCS=netbsd/ctl.c netbsd/compile.c netbsd/main.c netbsd/genget.c netbsd/commands.c netbsd/more.c netbsd/complete.c netbsd/passwd.c
SRCS+=netbsd/conf.c netbsd/sqlite3.c netbsd/who.c netbsd/version.c
CLEANFILES+=netbsd/compile.c
LDADD=-ledit -ltermcap -lsqlite3 -L/usr/local/lib -static

NOMAN=1

netbsd/compile.c: netbsd/compile.sh
	cd netbsd; sh ${.CURDIR}/netbsd/compile.sh
.endif

# For Darwin, brew install bmake and run `bmake`
.if $(OSNAME) == "Darwin"
SRCS=darwin/ctl.c darwin/compile.c darwin/main.c darwin/genget.c darwin/commands.c darwin/more.c darwin/complete.c darwin/passwd.c
SRCS+=darwin/conf.c darwin/sqlite3.c darwin/who.c darwin/version.c
CLEANFILES+=darwin/compile.c
LDADD=-ledit -ltermcap -lsqlite3 -L/usr/local/lib

darwin/compile.c: darwin/compile.sh
	cd darwin; sh ${.CURDIR}/darwin/compile.sh
.endif

.if $(OSNAME) == "Linux"
SRCS=linux/ctl.c linux/compile.c linux/main.c linux/genget.c linux/commands.c linux/more.c linux/complete.c linux/passwd.c
SRCS+=linux/conf.c linux/sqlite3.c linux/version.c linux/who.c
CLEANFILES+=linux/compile.c
LDADD=-lbsd -ledit -ltermcap -lsqlite3 -L/usr/local/lib

linux/compile.c: linux/compile.sh
	cd linux; sh ${.CURDIR}/linux/compile.sh
.endif

MAN=nsh.8

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
