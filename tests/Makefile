# nsh unit tests. Works with BSD make and GNU make.
#
#	make		build and run every test
#	make test	the same
#	make clean

CC?=		cc
CFLAGS+=	-g -O0 -Wall -I/usr/local/include
# externs.h insists on a version; the tests do not print it
CFLAGS+=	-DNSH_VERSION=test
TOP=		..

TESTS=		t_conftree t_facts t_genget t_makeargv t_stringlist \
		t_hashtable t_session t_ctlargs
SCRIPTS=	t_globals.sh

all: run

test: run

t_conftree: t_conftree.c ${TOP}/conftree.c test.h
	${CC} ${CFLAGS} -o $@ t_conftree.c ${TOP}/conftree.c

t_facts: t_facts.c ${TOP}/facts.c ${TOP}/facts.h test.h
	${CC} ${CFLAGS} -o $@ t_facts.c ${TOP}/facts.c

t_genget: t_genget.c ${TOP}/genget.c test.h
	${CC} ${CFLAGS} -o $@ t_genget.c ${TOP}/genget.c

t_makeargv: t_makeargv.c ${TOP}/makeargv.c test.h
	${CC} ${CFLAGS} -o $@ t_makeargv.c ${TOP}/makeargv.c

t_stringlist: t_stringlist.c ${TOP}/stringlist.c test.h
	${CC} ${CFLAGS} -o $@ t_stringlist.c ${TOP}/stringlist.c

t_hashtable: t_hashtable.c ${TOP}/hashtable.c test.h
	${CC} ${CFLAGS} -o $@ t_hashtable.c ${TOP}/hashtable.c

t_session: t_session.c ${TOP}/session.c ${TOP}/session.h test.h
	${CC} ${CFLAGS} -o $@ t_session.c ${TOP}/session.c

t_ctlargs: t_ctlargs.c ${TOP}/ctlargs.c ${TOP}/genget.c test.h
	${CC} ${CFLAGS} -o $@ t_ctlargs.c ${TOP}/ctlargs.c ${TOP}/genget.c

run: ${TESTS}
	sh ./run.sh ${TESTS} ${SCRIPTS}

clean:
	rm -f ${TESTS} *.core *.tmp

.PHONY: all test run clean
