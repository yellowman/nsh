/*
 * From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.64 2002/05/22
 * 08:21:02 deraadt Exp $
 */
/*-
 * Copyright (c) 1997, 1998, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include "externs.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"
#include "kfacts.h"
#include "args.h"

int process_media_commands(int, char *, uint64_t, struct cand *);
uint64_t get_media_subtype(uint64_t, const char *);
uint64_t get_media_options(uint64_t, const char *);
uint64_t lookup_media_word(const struct ifmedia_description *, uint64_t, const char *);
void conf_print_media_word(FILE *, uint64_t);
static int media_set(uint64_t);
static void media_line(char *, size_t, uint64_t);
static uint64_t cand_media(struct cand *, char *, uint64_t);
static int cand_setmedia(struct cand *, int, char *, uint64_t);

static const struct ifmedia_description ifm_subtype_descriptions[] =
    IFM_SUBTYPE_DESCRIPTIONS;

static const struct ifmedia_description ifm_option_descriptions[] =
    IFM_OPTION_DESCRIPTIONS;

/*
 * media and mediaopt name a subtype and options by the words of
 * ifm_subtype_descriptions and ifm_option_descriptions, which config
 * reads as those tables' indexes (media_index()): a subtype as its
 * index, and options as a set of their indexes' bits. Their apply
 * functions find what the indexes say for the interface's type
 */

/* The index of the description in desc that word names, or -1 */
static int
media_index(const struct ifmedia_description *desc, const char *word)
{
	int i;

	for (i = 0; desc[i].ifmt_string != NULL; i++)
		if (strcasecmp(desc[i].ifmt_string, word) == 0)
			return i;
	return -1;
}

/* options, between commas, as a set of their indexes' bits, into v */
static int
media_options_parse(const char *options, struct facts_value *v)
{
	char buf[256], *o, *p;
	long long bits = 0;
	int i;

	if (strlcpy(buf, options, sizeof(buf)) >= sizeof(buf)) {
		printf("%% get_media_options: too long: %s\n", options);
		return -1;
	}
	for (o = strtok_r(buf, ",", &p); o != NULL;
	    o = strtok_r(NULL, ",", &p)) {
		if ((i = media_index(ifm_option_descriptions, o)) == -1) {
			printf("%% get_media_options: unknown media option: "
			    "%s\n", o);
			return -1;
		}
		bits |= 1LL << i;
	}
	facts_i64(v, bits);
	return 0;
}

/* The options of type that bits, a set of their indexes, says, or -1 */
static uint64_t
media_options(uint64_t type, long long bits)
{
	const struct ifmedia_description *desc;
	uint64_t options = 0;
	size_t i;

	for (i = 0; i < nitems(ifm_option_descriptions) - 1; i++) {
		if ((bits & (1LL << i)) == 0)
			continue;
		desc = &ifm_option_descriptions[i];
		if (!IFM_TYPE_MATCH(desc->ifmt_word, type)) {
			printf("%% get_media_options: unknown %s media option: "
			    "%s\n", get_media_type_string(type),
			    desc->ifmt_string);
			return -1;
		}
		options |= IFM_OPTIONS(desc->ifmt_word);
	}
	return options;
}

int
intmedia(int argc, char **argv, ...)
{
	va_list ap;
	struct cand *cand;
	char *ifname;
	int ifs, set, n;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	cand = va_arg(ap, struct cand *);
	va_end(ap);

	/* with the media this interface supports */
	set = !NO_ARG(argv[0]);
	n = argc - (set ? 1 : 2);
	if (n >= 3 && isprefix(argv[argc - 2], "mediaopt"))
		n -= 2;
	if ((set && (n < 1 || n > 2)) || (!set && n > 2)) {
		printf("%% media <type> [instance] [mediaopt <options>]\n");
		printf("%% no media [type] [instance] [mediaopt <options>]\n");
		media_supported(ifs, ifname, "% ", "%   ", stdout);
		return -1;
	}
	return conf_line(CTX_IF, argc, argv, ifname, ifs, cand);
}

/* media's words: its subtype, instance and options */
int
intmedia_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	int i;

	/*
	 * A media word is taken whole, and some media are there only with
	 * an option, 1000baseT only with full-duplex on most phys
	 */
	if (argc >= 3 && isprefix(argv[argc - 2], "mediaopt")) {
		if (a->set && media_options_parse(argv[argc - 1],
		    &a->v[2]) == -1)
			return -1;
		argc -= 2;
	}
	if ((a->set && (argc < 1 || argc > 2)) || (!a->set && argc > 2)) {
		printf("%% media <type> [instance] [mediaopt <options>]\n");
		printf("%% no media [type] [instance] [mediaopt <options>]\n");
		return -1;
	}
	if (a->set) {
		i = media_index(ifm_subtype_descriptions, argv[0]);
		if (i == -1) {
			printf("%% get_media_subtype: unknown media subtype: "
			    "%s\n", argv[0]);
			return -1;
		}
		facts_i64(&a->v[0], i);
	}
	if (argc == 2 && args_word(c, &c->args[1], a, argv[1], &a->v[1]) == -1)
		return -1;
	return 0;
}

int
intmedia_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	uint64_t media_current, type, subtype, inst, options = 0;

	media_current = init_current_media(ifs, ifname, cand);

	if (media_current == -1) {
		if (errno == EINVAL)
			printf("%% This device does not support "
			    "media commands.\n");
		else
			printf("%% Failed to initialize media: %s\n",
			    strerror(errno));
		return -1;
	}

	if (v[1].type != FACT_NONE)
		inst = v[1].v.i;
	else
		inst = IFM_INST(media_current);

	type = IFM_TYPE(media_current);
	/* Look up the subtype */
	if (set)
		subtype = get_media_subtype(type,
		    ifm_subtype_descriptions[v[0].v.i].ifmt_string);
	else
		subtype = get_media_subtype(type, DEFAULT_MEDIA_TYPE);

	if (subtype == -1)
		return -1;
	if (set && v[2].type != FACT_NONE &&
	    (options = media_options(type, v[2].v.i)) == -1)
		return -1;

	/* Build the new media_current word */
	media_current = IFM_MAKEWORD(type, subtype, options, inst);

	return process_media_commands(ifs, ifname, media_current, cand);
}

/* mediaopt's options */
int
intmediaopt_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	if ((a->set && (argc != 1)) || (!a->set && (argc > 1))) {
		printf("%% mediaopt <option>\n");
		printf("%% no mediaopt [option]\n");
		return -1;
	}
	return argc == 1 ? media_options_parse(argv[0], &a->v[0]) : 0;
}

int
intmediaopt_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	uint64_t media_current, mediaopt;

        media_current = init_current_media(ifs, ifname, cand);

	if (media_current == -1) {
		if (errno == EINVAL)
			printf("%% This device does not support "
			    "media commands.\n");
		else
			printf("%% Failed to initialize media: %s\n",
			    strerror(errno));
		return -1;
	}

	if (v[0].type != FACT_NONE)
		mediaopt = media_options(IFM_TYPE(media_current), v[0].v.i);
	else
		mediaopt = IFM_OPTIONS(media_current);

	if (mediaopt == -1)
		return -1;

	if (set)
		media_current |= mediaopt;
	else
		media_current &= ~mediaopt;

	return process_media_commands(ifs, ifname, media_current, cand);
}

int
process_media_commands(int s, char *name, uint64_t media_current,
    struct cand *cand)
{
	struct ifreq ifr;

	if (cand != NULL)
		return cand_setmedia(cand, s, name, media_current);

	(void) strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_media = media_current;

	if (ioctl(s, SIOCSIFMEDIA, (caddr_t)&ifr) < 0) {
		printf("%% process_media_commands: SIOCSIFMEDIA: %s\n",
		    strerror(errno));
		return -1;
	}
	return 0;
}

uint64_t
init_current_media(int s, char *ifname, struct cand *cand)
{
	uint64_t media_current;

	if (kf_media(s, ifname, &media_current, NULL, NULL) == -1)
		return -1;

	/* Sanity. */
	if (IFM_TYPE(media_current) == 0) {
		printf("%% init_current_media: %s: no link type?\n", ifname);
		return -1;
	}

	if (cand != NULL)
		return cand_media(cand, ifname, IFM_TYPE(media_current));
	return media_current;
}

/*
 * The media word the candidate has for ifname, of the type the kernel
 * says the interface has: its media line, or autoselect
 */
static uint64_t
cand_media(struct cand *cand, char *ifname, uint64_t type)
{
	char line[256], *l, *p;
	const char *errmsg;
	uint64_t subtype, inst = 0, options = 0;

	if ((l = cand_line(cand, "media", 0)) == NULL)
		return IFM_MAKEWORD(type, IFM_AUTO, 0, 0);
	/* media <subtype> [instance] [mediaopt <options>] */
	strlcpy(line, l, sizeof(line));
	p = line;
	strsep(&p, " ");
	if ((subtype = get_media_subtype(type, strsep(&p, " "))) == -1)
		return -1;
	if (p != NULL && strncmp(p, "mediaopt ", 9) != 0) {
		inst = strtonum(strsep(&p, " "), 0, IFM_INST_MAX, &errmsg);
		if (errmsg)
			return -1;
	}
	if (p != NULL && strncmp(p, "mediaopt ", 9) == 0 &&
	    (options = get_media_options(type, p + 9)) == -1)
		return -1;
	return IFM_MAKEWORD(type, subtype, options, inst);
}

/*
 * SIOCSIFMEDIA in configure private: ifmedia_ioctl() takes a word the
 * driver lists, and conf_media_status() prints it if it was set
 */
static int
cand_setmedia(struct cand *cand, int s, char *ifname, uint64_t word)
{
	uint64_t *list, cur;
	char line[256];
	size_t i, n;

	if (kf_media(s, ifname, &cur, &list, &n) == -1) {
		printf("%% cand_setmedia: %s\n", strerror(errno));
		return -1;
	}
	for (i = 0; i < n && list[i] != word; i++)
		;
	free(list);
	if (i == n) {
		printf("%% process_media_commands: SIOCSIFMEDIA: %s\n",
		    strerror(EINVAL));
		return -1;
	}
	/* the kernel shows hidenwid and nobridge only in hostap mode */
	if (IFM_TYPE(word) == IFM_IEEE80211 &&
	    !(IFM_OPTIONS(word) & IFM_IEEE80211_HOSTAP) &&
	    cand_setting(cand, ST_OFF, "nwflag hidenwid nobridge") == -1)
		return -1;
	if (!media_set(word))
		return cand_setting(cand, ST_DEFAULT, "media");
	media_line(line, sizeof(line), word);
	return cand_setting(cand, ST_ON, "%s", line);
}

uint64_t
get_media_subtype(uint64_t type, const char *val)
{
	uint64_t	rval;

	rval = lookup_media_word(ifm_subtype_descriptions, type, val);
	if (rval == -1) {
		printf("%% get_media_subtype: unknown %s media subtype: %s\n",
		     get_media_type_string(type), val);
	}

	return (rval);
}

uint64_t
get_media_options(uint64_t type, const char *val)
{
	char           *optlist, *str;
	uint64_t	option, rval = 0;

	/* We muck with the string, so copy it. */
	optlist = (char *)strdup(val);
	if (optlist == NULL) {
		printf("%% get_media_options: strdup: %s\n", strerror(errno));
		return -1;
	}
	str = optlist;

	/*
         * Look up the options in the user-provided comma-separated list.
         */
	for (; (str = (char *)strtok(str, ",")) != NULL; str = NULL) {
		option = lookup_media_word(ifm_option_descriptions, type, str);
		if (option == -1) {
			printf("%% get_media_options: unknown %s media option: %s\n",
			     get_media_type_string(type), str);
			free(optlist);
			return -1;
		}
		rval |= IFM_OPTIONS(option);
	}

	free(optlist);
	return (rval);
}

uint64_t
lookup_media_word(const struct ifmedia_description *desc, uint64_t type, const char *val)
{
	for (; desc->ifmt_string != NULL; desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, type) &&
		    strcasecmp(desc->ifmt_string, val) == 0)
			return (desc->ifmt_word);
	}
	return (-1);
}

/* Does conf_media_status() print ifmw, as set rather than the default? */
static int
media_set(uint64_t ifmw)
{
	return IFM_SUBTYPE(ifmw) != IFM_AUTO || IFM_OPTIONS(ifmw) != 0 ||
	    IFM_INST(ifmw) != 0;
}

/* conf_print_media_word()'s line for ifmw */
static void
media_line(char *buf, size_t len, uint64_t ifmw)
{
	const struct ifmedia_description *desc;
	uint64_t seen_option = 0;
	char tmp[32];

	snprintf(buf, len, "media %s", get_media_subtype_string(ifmw));
	if (IFM_INST(ifmw) != 0) {
		snprintf(tmp, sizeof(tmp), " %llu", IFM_INST(ifmw));
		strlcat(buf, tmp, len);
	}

	/* Find options. */
	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL;
	    desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, ifmw) &&
		    (IFM_OPTIONS(ifmw) & IFM_OPTIONS(desc->ifmt_word)) != 0 &&
		    (seen_option & IFM_OPTIONS(desc->ifmt_word)) == 0) {
			strlcat(buf, seen_option ? "," : " mediaopt ", len);
			strlcat(buf, desc->ifmt_string, len);
			seen_option |= IFM_OPTIONS(desc->ifmt_word);
		}
	}
}

void
conf_print_media_word(FILE *output, uint64_t ifmw)
{
	char line[256];

	media_line(line, sizeof(line), ifmw);
	fprintf(output, " %s\n", line);
}

int
phys_status(int s, char *ifname, char *tmp_buf, char *tmp_buf2,
int buf_len, int buf2_len)
{
#ifdef NI_WITHSCOPEID
	const int       niflag = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int       niflag = NI_NUMERICHOST;
#endif
	struct if_laddrreq req;
	int port = 0;

	bzero(&req, sizeof(req));
	(void) strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	if (ioctl(s, SIOCGLIFPHYADDR, (caddr_t) &req) < 0)
		return -1;
	/* the kernel gives vxlan's port on the source */
	if (req.addr.ss_family == AF_INET)
		port = ((struct sockaddr_in *)&req.addr)->sin_port;
	else if (req.addr.ss_family == AF_INET6) {
		in6_fillscopeid((struct sockaddr_in6 *)&req.addr);
		port = ((struct sockaddr_in6 *)&req.addr)->sin6_port;
	}
	if (getnameinfo((struct sockaddr *)&req.addr, req.addr.ss_len,
	    tmp_buf, buf_len, 0, 0, niflag) != 0) {
		printf("%% phys_status: 0/getnameinfo failure\n");
		return (-1);
	}

	/* a tunnel made with tunneladdr has no destination */
	if (req.dstaddr.ss_family == AF_UNSPEC) {
		tmp_buf2[0] = '\0';
		return ntohs(port);
	}
	if (req.dstaddr.ss_family == AF_INET6)
		in6_fillscopeid((struct sockaddr_in6 *) & req.dstaddr);
	if (getnameinfo((struct sockaddr *)&req.dstaddr, req.dstaddr.ss_len,
	    tmp_buf2, buf2_len, 0, 0, niflag) != 0) {
		printf("%% phys_status: 1/getnameinfo failure\n");
		return -1;
	}
	return ntohs(port);
}

int
conf_media_status(FILE *output, int s, char *ifname)
{
	int rval = 0;
	uint64_t *media_list;
	struct ifmediareq ifmr;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		if (errno != ENOTTY)
			printf("%% conf_media_status: 1/SIOCGIFMEDIA: %s\n",
			    strerror(errno));
		return 0;
	}

	if (ifmr.ifm_count == 0)
		return 0;

	media_list = calloc(ifmr.ifm_count, sizeof(*media_list));
	if (media_list == NULL) {
		printf("%% conf_media_status: calloc: %s\n", strerror(errno));
		return 0;
	}
	ifmr.ifm_ulist = media_list;

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		printf("%% conf_media_status: 2/SIOCGIFMEDIA: %s\n",
		    strerror(errno));
		free(media_list);
		return 0;
	}

	if (media_set(ifmr.ifm_current)) {
		/* a media type was set manually */
		rval = 1;
		conf_print_media_word(output, ifmr.ifm_current);
	}

	free(media_list);
	return rval;
}

static void
media_record(struct facts_out *o, char *ifname, uint64_t role, uint64_t word)
{
	struct facts_value	 v[MEDIA_NFIELDS];
	const char		*s;
	uint64_t		 seen = 0;
	char			 options[128];

	memset(v, 0, sizeof(v));
	facts_u64(&v[MEDIA_ROLE], role);
	facts_u64(&v[MEDIA_WORD], word);
	if ((s = get_ifm_type_str(word)) != NULL)
		facts_string(&v[MEDIA_TYPE], s);
	if ((s = get_ifm_subtype_str(word)) != NULL)
		facts_string(&v[MEDIA_SUBTYPE], s);
	facts_u64(&v[MEDIA_INSTANCE], IFM_INST(word));
	get_ifm_options_str(options, sizeof(options), word, &seen);
	if (options[0] != '\0')
		facts_string(&v[MEDIA_OPTIONS], options);
	facts_string(&v[MEDIA_IF], ifname);
	facts_record(o, &kind_media, v);
}

/*
 * ifname's current and active media, and with supported, those it
 * supports; in ifv, its record, their count and status
 */
void
media_facts(struct facts_out *o, int s, char *ifname, struct facts_value *ifv,
    int supported)
{
	uint64_t		*media_list = NULL;
	struct ifmediareq	 ifmr;
	int			 i;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		if (errno != ENOTTY)
			printf("%% media_status: SIOCGIFMEDIA: %s\n",
			    strerror(errno));
		return;
	}
	if (ifmr.ifm_count > 0) {
		media_list = calloc(ifmr.ifm_count, sizeof(*media_list));
		if (media_list == NULL) {
			printf("%% media_status: calloc: %s\n",
			    strerror(errno));
			return;
		}
		ifmr.ifm_ulist = media_list;
		if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
			printf("%% media_status: SIOCGIFMEDIA: %s\n",
			    strerror(errno));
			free(media_list);
			return;
		}
	}
	facts_u64(&ifv[IF_MEDIACOUNT], ifmr.ifm_count);
	facts_u64(&ifv[IF_MEDIASTATUS], ifmr.ifm_status);
	media_record(o, ifname, MEDIA_CURRENT, ifmr.ifm_current);
	media_record(o, ifname, MEDIA_ACTIVE, ifmr.ifm_active);
	for (i = 0; supported && media_list != NULL && i < ifmr.ifm_count; i++)
		media_record(o, ifname, MEDIA_SUPPORTED, media_list[i]);
	free(media_list);
}

void
media_supported(int s, char *ifname, char *hdr_delim, char *body_delim,
    FILE *outfile)
{
	u_int64_t *media_list;
	int i, type, printed_type;
	struct ifmediareq ifmr;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		if (errno != ENOTTY)
			printf("%% media_supported: 1/SIOCGIFMEDIA: %s\n",
			    strerror(errno));
		return;
	}

	media_list = calloc(ifmr.ifm_count, sizeof(*media_list));
	if (media_list == NULL) {
		printf("%% media_supported: calloc: %s\n", strerror(errno));
		return;
	}
	ifmr.ifm_ulist = media_list;

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		printf("%% media_supported: 2/SIOCGIFMEDIA: %s\n",
		    strerror(errno));
		return;
	}

	for (type = IFM_NMIN; type <= IFM_NMAX; type += IFM_NMIN) {
		for (i = 0, printed_type = 0; i < ifmr.ifm_count; i++) {
			if (IFM_TYPE(media_list[i]) == type) {
				if (printed_type == 0) {
				    fprintf(outfile,
				        "%sSupported media types on %s:\n",
				        hdr_delim, ifname);
				    printed_type = 1;
				}
				fprintf(outfile, "%s", body_delim);
				print_media_word(media_list[i], 0, 1, outfile);
				fputc('\n', outfile);
			}
		}
	}

	free(media_list);
	return;
}
