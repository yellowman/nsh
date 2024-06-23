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

int init_current_media(int, char *);
void process_media_commands(int, char *, int);
const char *get_media_type_string(uint64_t);
const char *get_media_subtype_string(uint64_t);
uint64_t get_media_subtype(uint64_t, const char *);
uint64_t get_media_options(uint64_t, const char *);
uint64_t lookup_media_word(const struct ifmedia_description *, uint64_t, const char *);
void print_media_word(uint64_t, int, int, FILE *);
void conf_print_media_word(FILE *, int);

const int ifm_status_valid_list[] =
    IFM_STATUS_VALID_LIST;

const struct ifmedia_status_description ifm_status_descriptions[] =
    IFM_STATUS_DESCRIPTIONS;

const struct ifmedia_description ifm_type_descriptions[] =
    IFM_TYPE_DESCRIPTIONS;

const struct ifmedia_description ifm_subtype_descriptions[] =
    IFM_SUBTYPE_DESCRIPTIONS;

const struct ifmedia_description ifm_option_descriptions[] =
    IFM_OPTION_DESCRIPTIONS;

int
intmedia(char *ifname, int ifs, int argc, char **argv)
{
	const char *errmsg = NULL;
	uint64_t set, media_current, type, subtype, inst;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argv++;
	argc--;

	if ((set && (argc < 1 || argc > 2)) || (!set && argc > 2)) {
		printf("%% media <type> [instance]\n");
		printf("%% no media [type] [instance]\n");
		media_supported(ifs, ifname, "% ", "%   ", stdout);
		return(0);
	}

	media_current = init_current_media(ifs, ifname);

	if (media_current == -1) {
		if (errno == EINVAL)
			printf("%% This device does not support "
			    "media commands.\n");
		else
			printf("%% Failed to initialize media: %s\n",
			    strerror(errno));
		return(0);
	}

	if (argc == 2) {
		inst = strtonum(argv[1], 0, IFM_INST_MAX, &errmsg);
		if (errmsg) {
			printf("%% Invalid media instance: %s: %s\n", argv[1],
			    errmsg);
			return(0);
		}
	} else {
		inst = IFM_INST(media_current);
	}

	type = IFM_TYPE(media_current);
	/* Look up the subtype */
	if (set)
		subtype = get_media_subtype(type, argv[0]);
	else
		subtype = get_media_subtype(type, DEFAULT_MEDIA_TYPE);

	if (subtype == -1)
		return(0);

	/* Build the new media_current word */
	media_current = IFM_MAKEWORD(type, subtype, 0, inst);

	process_media_commands(ifs, ifname, media_current);

	return(0);
}

int
intmediaopt(char *ifname, int ifs, int argc, char **argv)
{
	int set, media_current, mediaopt;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argv++;
	argc--;

	if ((set && (argc != 1)) || (!set && (argc > 1))) {
		printf("%% mediaopt <option>\n");
		printf("%% no mediaopt [option]\n");
		return(0);
	}

        media_current = init_current_media(ifs, ifname);

	if (media_current == -1) {
		if (errno == EINVAL)
			printf("%% This device does not support "
			    "media commands.\n");
		else
			printf("%% Failed to initialize media: %s\n",
			    strerror(errno));
		return(0);
	}

	if (argc == 1)
		mediaopt = get_media_options(IFM_TYPE(media_current), argv[0]);
	else
		mediaopt = IFM_OPTIONS(media_current);

	if (mediaopt == -1)
		return(0);

	if (set)
		media_current |= mediaopt;
	else
		media_current &= ~mediaopt;

	process_media_commands(ifs, ifname, media_current);

	return(0);
}

void
process_media_commands(int s, char *name, int media_current)
{
	struct ifreq ifr;

	(void) strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_media = media_current;

	if (ioctl(s, SIOCSIFMEDIA, (caddr_t)&ifr) < 0)
		printf("%% process_media_commands: SIOCSIFMEDIA: %s\n",
		    strerror(errno));
}

int
init_current_media(int s, char *ifname)
{
	int media_current;
	struct ifmediareq ifmr;

	(void) memset(&ifmr, 0, sizeof(ifmr));
	(void) strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t) & ifmr) < 0) {
		/*
		 * If we get E2BIG, the kernel is telling us
		 * that there are more, so we can ignore it.
		 */
		if (errno != E2BIG)
			return(-1);
	}
	media_current = ifmr.ifm_current;

	/* Sanity. */
	if (IFM_TYPE(media_current) == 0) {
		printf("%% init_current_media: %s: no link type?\n", ifname);
		return(-1);
	}

	return(media_current);
}

const char *
get_ifm_linkstate_str(struct ifmediareq *ifmr)
{
	const uint64_t ifm_status_valid_list[] = IFM_STATUS_VALID_LIST;
	const struct ifmedia_status_description *ifms;
	int bitno;

	if ((ifmr->ifm_status & IFM_AVALID) == 0)
		return NULL;

	for (bitno = 0; ifm_status_valid_list[bitno] != 0; bitno++) {
		for (ifms = ifm_status_descriptions;
		    ifms->ifms_valid != 0; ifms++) {
			if (ifms->ifms_type != IFM_TYPE(ifmr->ifm_current) ||
			    ifms->ifms_valid != ifm_status_valid_list[bitno])
				continue;
			return IFM_STATUS_DESC(ifms, ifmr->ifm_status);
		}
	}

	return NULL;
}

const char *
get_ifm_options_str(char *buf, size_t size, uint64_t ifmw,
    uint64_t *seen_options)
{
	const struct ifmedia_description *desc;

	buf[0] = '\0';

	/* Find options. */
	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, ifmw) &&
		  (IFM_OPTIONS(ifmw) & IFM_OPTIONS(desc->ifmt_word)) != 0 &&
		    (*seen_options & IFM_OPTIONS(desc->ifmt_word)) == 0) {
			if (buf[0] != '\0')
				strlcat(buf, " ", size);
			strlcat(buf, desc->ifmt_string, size);
			*seen_options |= IFM_OPTIONS(desc->ifmt_word);
		}
	}

	return buf;
}

const char *
get_ifm_type_str(uint64_t mword)
{
	const struct ifmedia_description *desc;

	for (desc = ifm_type_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE(mword) == desc->ifmt_word)
			return (desc->ifmt_string);
	}

	return NULL;
}

const char     *
get_ifm_subtype_str(uint64_t mword)
{
	const struct ifmedia_description *desc;

	for (desc = ifm_subtype_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, mword) &&
		    IFM_SUBTYPE(desc->ifmt_word) == IFM_SUBTYPE(mword))
			return (desc->ifmt_string);
	}

	return NULL;
}

const char     *
get_media_type_string(uint64_t mword)
{
	const char *s;

	s = get_ifm_type_str(mword);
	if (s != NULL)
		return (s);

	return ("<unknown type>");
}

const char     *
get_media_subtype_string(uint64_t mword)
{
	const char *s;

	s = get_ifm_subtype_str(mword);
	if (s != NULL)
		return (s);

	return ("<unknown subtype>");
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
		return(-1);
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
			return(-1);
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

void
print_media_word(uint64_t ifmw, int print_type, int as_syntax, FILE *outfile)
{
	const struct ifmedia_description *desc;
	uint64_t	seen_option = 0;

	if (print_type)
		fprintf(outfile, "%s ", get_media_type_string(ifmw));
	fprintf(outfile, "%s%s", as_syntax ? "media " : "",
	       get_media_subtype_string(ifmw));
	if (IFM_INST(ifmw) != 0)
		fprintf(outfile, " %lld", IFM_INST(ifmw));

	/* Find options. */
	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, ifmw) &&
		  (IFM_OPTIONS(ifmw) & IFM_OPTIONS(desc->ifmt_word)) != 0 &&
		    (seen_option & IFM_OPTIONS(desc->ifmt_word)) == 0) {
			if (seen_option == 0)
				fprintf(outfile, "%s",
				    as_syntax ? ", mediaopt " : " ");
			fprintf(outfile, "%s%s", seen_option ? "," : "",
			       desc->ifmt_string);
			seen_option |= IFM_OPTIONS(desc->ifmt_word);
		}
	}
}

void
conf_print_media_word(FILE *output, int ifmw)
{
	const struct ifmedia_description *desc;
	int seen_option = 0;

	fprintf(output, " media %s", get_media_subtype_string(ifmw));
	if (IFM_INST(ifmw) != 0)
		printf(" %llu", IFM_INST(ifmw));
	fprintf(output, "\n");

	/* Find options. */
	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL;
	    desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, ifmw) &&
		    (IFM_OPTIONS(ifmw) & IFM_OPTIONS(desc->ifmt_word)) != 0 &&
		    (seen_option & IFM_OPTIONS(desc->ifmt_word)) == 0) {
			if (seen_option == 0)
				fprintf(output, " mediaopt ");
			fprintf(output, "%s%s", seen_option ? "," : "",
			    desc->ifmt_string);
			seen_option |= IFM_OPTIONS(desc->ifmt_word);
		}
	}
	if (seen_option)
		fprintf(output, "\n");
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
	int dstport = 0;

	bzero(&req, sizeof(req));
	(void) strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	if (ioctl(s, SIOCGLIFPHYADDR, (caddr_t) &req) < 0)
		return(-1);
	if (req.addr.ss_family == AF_INET6)
		in6_fillscopeid((struct sockaddr_in6 *)&req.addr);
	if (getnameinfo((struct sockaddr *)&req.addr, req.addr.ss_len,
	    tmp_buf, buf_len, 0, 0, niflag) != 0) {
		printf("%% phys_status: 0/getnameinfo failure\n");
		return (-1);
	}

	if (req.dstaddr.ss_family == AF_INET) {
		dstport = ((struct sockaddr_in *)&req.dstaddr)->sin_port;
	} else if (req.dstaddr.ss_family == AF_INET6) {
		in6_fillscopeid((struct sockaddr_in6 *) & req.dstaddr);
		dstport = ((struct sockaddr_in6 *)&req.dstaddr)->sin6_port;
	}
	if (getnameinfo((struct sockaddr *)&req.dstaddr, req.dstaddr.ss_len,
	    tmp_buf2, buf2_len, 0, 0, niflag) != 0) {
		printf("%% phys_status: 1/getnameinfo failure\n");
		return(-1);
	}
	return(ntohs(dstport));
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
		return(0);
	}

	if (ifmr.ifm_count == 0)
		return(0);

	media_list = calloc(ifmr.ifm_count, sizeof(*media_list));
	if (media_list == NULL) {
		printf("%% conf_media_status: calloc: %s\n", strerror(errno));
		return(0);
	}
	ifmr.ifm_ulist = media_list;

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		printf("%% conf_media_status: 2/SIOCGIFMEDIA: %s\n",
		    strerror(errno));
		free(media_list);
		return(0);
	}

	if (ifmr.ifm_current >= ifmr.ifm_active) {
		/* a media type was set manually */
		rval = 1;
		conf_print_media_word(output, ifmr.ifm_current);
	}

	free(media_list);
	return(rval);
}

int
media_status(int s, char *ifname, char *delim, FILE *outfile)
{
	uint64_t *media_list;
	struct ifmediareq ifmr;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		if (errno != ENOTTY) {
			printf("%% media_status: SIOCGIFMEDIA: %s\n",
			    strerror(errno));
			return 1;
		}
		return 0;
	}

	if (ifmr.ifm_count == 0) {
		if (verbose)
			printf("%% %s: No media types?\n", ifname);
		return 0;
	}

	media_list = calloc(ifmr.ifm_count, sizeof(*media_list));
	if (media_list == NULL) {
		printf("%% media_status: calloc: %s\n", strerror(errno));
		return 1;
	}
	ifmr.ifm_ulist = media_list;

	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
		printf("%% media_status: SIOCGIFMEDIA: %s\n", strerror(errno));
		free(media_list);
		return 1;
	}

	fprintf(outfile, "%s", delim);
	print_media_word(ifmr.ifm_current, 0, 0, outfile);
	if (ifmr.ifm_active != ifmr.ifm_current) {
		fprintf(outfile, " (");
		print_media_word(ifmr.ifm_active, 0, 0, outfile);
		fputc(')', outfile);
	}

	if (ifmr.ifm_status & IFM_AVALID) {
		const struct ifmedia_status_description *ifms;
		int bitno, found = 0;

		fprintf(outfile, ", status ");
		for (bitno = 0; ifm_status_valid_list[bitno] != 0; bitno++) {

			for (ifms = ifm_status_descriptions;
			     ifms->ifms_valid != 0; ifms++) {

				if (ifms->ifms_type !=
				      IFM_TYPE(ifmr.ifm_current) ||
				    ifms->ifms_valid !=
				      ifm_status_valid_list[bitno])
					continue;

				fprintf(outfile, "%s%s", found ? ", " : "",
				    IFM_STATUS_DESC(ifms, ifmr.ifm_status));
				found = 1;

				/*
				 * For each valid indicator bit, there's only
				 * one entry for each media type, so
				 * terminate the inner loop now.
				 */
				break;
			}
		}
		if (found == 0)
			fprintf(outfile, "unknown");
	}
	fputc('\n', outfile);

	free(media_list);
	return 0;
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
