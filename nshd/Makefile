#
PROG=	nshd
MAN=	nshd.8

.PATH:	${.CURDIR}/..

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
CFLAGS+=-I${.CURDIR} -I${.CURDIR}/.. -I/usr/local/include
CPPFLAGS+=-DNSH_VERSION=${NSH_VERSION}

SRCS=	nshd.c control.c log.c showproc.c frontend.c configproc.c
SRCS+=	systemproc.c archive.c stubs.c confirm.c
# nsh's own, which system runs
SRCS+=	arp.c compile.c genget.c commands.c bgpcommands.c stats.c kroute.c
SRCS+=	ctl.c show.c if.c version.c route.c conf.c complete.c editing.c ieee80211.c
SRCS+=	bridge.c tunnel.c media.c sysctl.c passwd.c pfsync.c carp.c
SRCS+=	trunk.c who.c more.c stringlist.c utils.c sqlite3.c ppp.c prompt.c
SRCS+=	nopt.c pflow.c wg.c nameserver.c ndp.c umb.c utf8.c cmdargs.c ctlargs.c
SRCS+=	helpcommands.c makeargv.c hashtable.c conftree.c candidate.c settings.c
SRCS+=	kernel.c commit.c facts.c showfacts.c autoconf.c session.c kfacts.c
SRCS+=	renderif.c renderrt.c rendersys.c
CLEANFILES+=compile.c

LDADD=	-levent -lutil -ledit -ltermcap
DPADD=	${LIBEVENT} ${LIBUTIL} ${LIBEDIT} ${LIBTERMCAP}

.if make(static)
NSH_SQLITE_LIBS!=/usr/bin/pkg-config --libs --static sqlite3
.else
NSH_SQLITE_LIBS!=/usr/bin/pkg-config --libs sqlite3
.endif
LDADD+=${NSH_SQLITE_LIBS}

.if make(static)
LDADD+=-static
.endif

static: all

compile.c: compile.sh
	sh ${.CURDIR}/../compile.sh

.include <bsd.prog.mk>
