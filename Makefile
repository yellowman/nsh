#
SUBDIR += nsh bgpnsh nshd nshdeck

.PHONY: release dist

.include "nsh-version.mk"

# convenience target for producing statically linked binaries
static:
	${MAKE} -C ${.CURDIR}/nsh static
	${MAKE} -C ${.CURDIR}/bgpnsh static
	${MAKE} -C ${.CURDIR}/nshd static

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

.include <bsd.subdir.mk>
