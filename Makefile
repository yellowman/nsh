#
PROG= nsh

.if make(install)
DESTDIR?=/usr/local
BINDIR?=/bin
MANDIR?=/man/man
.endif

# For use with flashrd:
#CFLAGS=-O -DDHCPLEASES=\"/flash/dhcpd.leases\" -Wmissing-prototypes -Wformat -Wall -Wpointer-arith -Wbad-function-cast #-W
CFLAGS?=-O
CFLAGS+=-Wmissing-prototypes -Wformat -Wall -Wbad-function-cast -I/usr/local/include #-W -Wpointer-arith

SRCS=arp.c compile.c main.c genget.c commands.c stats.c kroute.c
SRCS+=ctl.c show.c if.c version.c route.c conf.c complete.c ieee80211.c
SRCS+=bridge.c tunnel.c media.c sysctl.c passwd.c pfsync.c carp.c
SRCS+=trunk.c who.c more.c stringlist.c utils.c sqlite3.c ppp.c
SRCS+=nopt.c pflow.c wg.c nameserver.c
CLEANFILES+=compile.c
LDADD=-ledit -ltermcap -lsqlite3 -L/usr/local/lib #-static

MAN=nsh.8

compile.c: compile.sh
	sh ${.CURDIR}/compile.sh

.include <bsd.prog.mk>
