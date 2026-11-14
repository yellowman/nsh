/*
 * Copyright (c) 2004 Chris Cappuccio <chris@nmedia.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/ip_ipsp.h>
#include <net/if_pfsync.h>
#include "externs.h"
#include "settings.h"
#include "facts.h"
#include "args.h"

#define PFSYNC_MAXUPDATES 128

static int pfsync_get(int, struct ifreq *, struct cand *);
static int cand_getpfsync(struct cand *, char *, struct pfsyncreq *);
static int cand_setpfsync(struct cand *, char *, struct pfsyncreq *);

/* Do SIOCGETPFSYNC, or in configure private, read the candidate */
static int
pfsync_get(int ifs, struct ifreq *ifr, struct cand *cand)
{
	if (cand != NULL)
		return cand_getpfsync(cand, ifr->ifr_name,
		    (struct pfsyncreq *)ifr->ifr_data);
	return ioctl(ifs, SIOCGETPFSYNC, (caddr_t)ifr);
}

/* SIOCGETPFSYNC in configure private: what conf_pfsync() printed */
static int
cand_getpfsync(struct cand *cand, char *ifname, struct pfsyncreq *preq)
{
	char *l, *w;
	const char *errmsg;

	if (!cand_takes(ifname, SIOCSETPFSYNC)) {
		errno = ENOTTY;
		return -1;
	}
	memset(preq, 0, sizeof(*preq));
	preq->pfsyncr_syncpeer.s_addr = htonl(INADDR_PFSYNC_GROUP);
	preq->pfsyncr_maxupdates = PFSYNC_MAXUPDATES;
	if ((l = cand_line(cand, "syncdev", 0)) != NULL)
		strlcpy(preq->pfsyncr_syncdev, l + strlen("syncdev "),
		    sizeof(preq->pfsyncr_syncdev));
	if ((l = cand_line(cand, "syncpeer", 0)) != NULL)
		inet_pton(AF_INET, l + strlen("syncpeer "),
		    &preq->pfsyncr_syncpeer);
	if ((l = cand_line(cand, "maxupd", 0)) != NULL) {
		/* maxupd n [defer] */
		l += strlen("maxupd ");
		if ((w = strchr(l, ' ')) != NULL) {
			*w = '\0';
			preq->pfsyncr_maxupdates = strtonum(l, 0, 255, &errmsg);
			*w = ' ';
			preq->pfsyncr_defer = strcmp(w + 1, "defer") == 0;
		} else
			preq->pfsyncr_maxupdates = strtonum(l, 0, 255, &errmsg);
	}
	return 0;
}

/*
 * SIOCSETPFSYNC in configure private: what pfsync_ioctl() refuses is
 * refused with its errno, and the lines become what conf_pfsync() would
 * print of the result
 */
static int
cand_setpfsync(struct cand *cand, char *ifname, struct pfsyncreq *preq)
{
	int r = 0;

	if (preq->pfsyncr_maxupdates > 255) {
		errno = EINVAL;
		return -1;
	}
	if (preq->pfsyncr_syncdev[0] != '\0' &&
	    !cand_hasif(cand, preq->pfsyncr_syncdev)) {
		errno = ENXIO;
		return -1;
	}
	if (preq->pfsyncr_syncpeer.s_addr == INADDR_ANY)
		preq->pfsyncr_syncpeer.s_addr = htonl(INADDR_PFSYNC_GROUP);

	if (preq->pfsyncr_syncdev[0] != '\0')
		r |= cand_setting(cand, ST_ON, "syncdev %s",
		    preq->pfsyncr_syncdev);
	else
		r |= cand_setting(cand, ST_DEFAULT, "syncdev");
	if (preq->pfsyncr_syncpeer.s_addr != htonl(INADDR_PFSYNC_GROUP))
		r |= cand_setting(cand, ST_ON, "syncpeer %s",
		    inet_ntoa(preq->pfsyncr_syncpeer));
	else
		r |= cand_setting(cand, ST_DEFAULT, "syncpeer");
	if (preq->pfsyncr_maxupdates != PFSYNC_MAXUPDATES ||
	    preq->pfsyncr_defer)
		r |= cand_setting(cand, ST_ON, "maxupd %d%s",
		    preq->pfsyncr_maxupdates,
		    preq->pfsyncr_defer ? " defer" : "");
	else
		r |= cand_setting(cand, ST_DEFAULT, "maxupd");
	return r;
}

/*
 * pfsync_up() refuses a syncdev that does not do multicast when the
 * syncpeer is a multicast address (ENODEV). A syncpeer of 0.0.0.0 means
 * the pfsync group, which is one. Returns 1 if dev can be the syncdev.
 */
static int
pfsync_mcast(int ifs, char *dev, struct in_addr peer, struct cand *cand)
{
	in_addr_t p = peer.s_addr == INADDR_ANY ?
	    htonl(INADDR_PFSYNC_GROUP) : peer.s_addr;

	if (dev[0] == '\0' || !IN_MULTICAST(ntohl(p)) ||
	    ((cand != NULL ? cand_getflags(dev, ifs) : get_ifflags(dev, ifs)) &
	    IFF_MULTICAST))
		return 1;
	printf("%% %s does not do multicast, which syncpeer %s needs\n", dev,
	    inet_ntoa(*(struct in_addr *)&p));
	return 0;
}

/*
 * SIOCSETPFSYNC. pfsync refuses a new syncdev or syncpeer while it runs
 * (EBUSY), so then it goes down for the change, and comes back up if the
 * change failed or it still has a syncdev.
 */
static int
pfsync_set(int ifs, struct ifreq *ifr, struct cand *cand)
{
	struct pfsyncreq *preq = (struct pfsyncreq *)ifr->ifr_data;
	int flags, ret, saved;

	if (cand != NULL)
		return cand_setpfsync(cand, ifr->ifr_name, preq);
	if ((ret = ioctl(ifs, SIOCSETPFSYNC, (caddr_t)ifr)) == 0 ||
	    errno != EBUSY)
		return ret;
	if (!((flags = get_ifflags(ifr->ifr_name, ifs)) & IFF_UP)) {
		errno = EBUSY;
		return ret;
	}
	set_ifflags(ifr->ifr_name, ifs, flags & ~IFF_UP);
	ret = ioctl(ifs, SIOCSETPFSYNC, (caddr_t)ifr);
	saved = errno;
	/* left down, it is not what was asked */
	if ((ret == -1 || preq->pfsyncr_syncdev[0] != '\0') &&
	    set_ifflags(ifr->ifr_name, ifs, flags) == -1 && ret == 0)
		return -1;
	errno = saved;
	return ret;
}

int
intsyncdev_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	char dev[IFNAMSIZ] = "";

	if (set)
		args_string(&v[0], dev, sizeof(dev));
	if (!isprefix("pfsync", ifname)) {
		printf("%% syncdev is only for pfsync devices\n");
		return -1;
	}

	bzero((char *) &preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (pfsync_get(ifs, &ifr, cand) == -1) {
		printf("%% intsyncdev: SIOCGETPFSYNC: %s\n", strerror(errno));
		return -1;
	}

	if (set &&
	    !(cand != NULL ? cand_hasif(cand, dev) : is_valid_ifname(dev))) {
		printf("%% Interface not found: %s\n", dev);
		return -1;
	}
	strlcpy(preq.pfsyncr_syncdev, dev, sizeof(preq.pfsyncr_syncdev));
	if (!pfsync_mcast(ifs, preq.pfsyncr_syncdev,
	    preq.pfsyncr_syncpeer, cand))
		return -1;

	if (pfsync_set(ifs, &ifr, cand) == -1) {
		if (errno == ENOBUFS)
			printf("%% Invalid synchronization interface: %s\n",
			    dev);
		else
			printf("%% intsyncdev: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
		return -1;
	}
	if (cand != NULL) {
		/* syncdev raises it, and without one it is down */
		if (set)
			return cand_upline(cand, ifname, 1);
		return cand_setting(cand, ST_ON, "shutdown");
	}
	/* pfsync_up() needs the syncdev */
	if (set && set_ifflag(ifs, ifname, IFF_UP) != 0)
		return -1;
	return (0);
}

int
intsyncpeer_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	int r = 0;

	if (!isprefix("pfsync", ifname)) {
		printf("%% syncpeer is only for pfsync devices\n");
		return -1;
	}

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) &preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (pfsync_get(ifs, &ifr, cand) == -1) {
			printf("%% intsyncpeer: SIOCGETPFSYNC: %s\n",
			    strerror(errno));
		return -1;
	}

	if (set)
		memcpy(&preq.pfsyncr_syncpeer, v[0].v.a.bytes,
		    sizeof(preq.pfsyncr_syncpeer));
	else
		preq.pfsyncr_syncpeer.s_addr = 0;
	/* pfsync_up() refuses it (EDESTADDRREQ) */
	if (preq.pfsyncr_syncpeer.s_addr == INADDR_BROADCAST) {
		printf("%% syncpeer cannot be the broadcast address\n");
		return -1;
	}
	if (!pfsync_mcast(ifs, preq.pfsyncr_syncdev,
	    preq.pfsyncr_syncpeer, cand))
		return -1;

	if (pfsync_set(ifs, &ifr, cand) == -1) {
			printf("%% intsyncpeer: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
		r = -1;
	}

	return r;
}

int
intmaxupd_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	struct pfsyncreq preq;

	bzero((char *) &preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (pfsync_get(ifs, &ifr, cand) == -1) {
		printf("%% intmaxupd: SIOCGETPFSYNC: %s\n", strerror(errno));
		return -1;
	}
	if (set) {
		preq.pfsyncr_maxupdates = v[0].v.i;
		preq.pfsyncr_defer = v[1].type != FACT_NONE;
	} else {
		preq.pfsyncr_maxupdates = PFSYNC_MAXUPDATES;
		preq.pfsyncr_defer = 0;
	}

	if (pfsync_set(ifs, &ifr, cand) == -1) {
		if (errno == EINVAL)
			printf("%% maxupd value out of range\n");
		else
			printf("%% intmaxupd: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
		return -1;
	}
	return (0);
}

int
conf_pfsync(FILE *output, int s, char *ifname)
{
	struct ifreq ifr;
	struct pfsyncreq preq;

	bzero((char *) &preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGETPFSYNC, (caddr_t) & ifr) == -1)
		return (0);

	/* syncdev must be first */
	if (preq.pfsyncr_syncdev[0] != '\0')
		fprintf(output, " syncdev %s\n", preq.pfsyncr_syncdev);
	/* syncpeer */
	if (preq.pfsyncr_syncpeer.s_addr != htonl(INADDR_PFSYNC_GROUP))
		fprintf(output, " syncpeer %s\n", inet_ntoa(
		    preq.pfsyncr_syncpeer));
	if (preq.pfsyncr_maxupdates != PFSYNC_MAXUPDATES || preq.pfsyncr_defer) {
		fprintf(output, " maxupd %i",
		    preq.pfsyncr_maxupdates);
		if (preq.pfsyncr_defer)
			fprintf(output, " defer");
		fprintf(output, "\n");
	}
	return (0);
}
