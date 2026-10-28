/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
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

/*
 * What configure private reads of the kernel, and nothing else. nsh
 * asks the kernel. nshd's config cannot, so it reads what system's last
 * snapshot found, as facts (kfacts.c, kfacts_set()).
 */

#ifndef KFACTS_H
#define KFACTS_H

#define KF_LLADDR	sizeof("00:00:00:00:00:00")

/* an interface, as configure private reads it */
struct kif {
	char		 name[IFNAMSIZ];
	unsigned int	 index;
	int		 flags;		/* SIOCGIFFLAGS */
	int		 type;		/* if_data's ifi_type */
	int		 caps;		/* and ifi_capabilities */
	int		 wifi;		/* SIOCG80211NWID answers */
	char		 lladdr[KF_LLADDR];	/* the one it came with, or "" */
	int		 hasll6;
	struct in6_addr	 ll6;		/* its link-local address */
	uint64_t	 media;		/* SIOCGIFMEDIA's current word, or 0 */
	uint64_t	*medias;	/* and the words its driver lists */
	size_t		 nmedias;
};

struct kfacts {
	struct kif	*ifs;
	size_t		 nifs;
	char		(*cloners)[IFNAMSIZ];
	size_t		 ncloners;
	char		(*groups)[IFNAMSIZ];	/* the interface groups */
	size_t		 ngroups;
	unsigned char	 rtables[256];	/* 1 for each table that exists */
	int		 dhcpleased;	/* its control socket answers */
	int		 failed;	/* kfacts_record() could not keep one */
};

void		 kfacts_set(struct kfacts *);
struct kfacts	*kfacts_scan(void);
void		 kfacts_free(struct kfacts *);

unsigned int	 kf_index(char *);
int		 kf_valid(char *);
int		 kf_flags(char *, int);
int		 kf_type(char *);
int		 kf_caps(char *);
int		 kf_wifi(char *);
char		*kf_lladdr(char *);
int		 kf_ll6(char *, struct in6_addr *);
int		 kf_media(int, char *, uint64_t *, uint64_t **, size_t *);
int		 kf_cloner(char *, size_t);
int		 kf_rtable(int);
int		 kf_dhcpleased(void);

/* the kinds of names kf_names() lists for completion */
#define KF_IFS		0	/* the interfaces */
#define KF_GROUPS	1	/* their groups */
#define KF_BRIDGES	2	/* the bridges */
#define KF_RTABLES	3	/* the routing tables, except table 0 */
#ifdef _STRINGLIST_H
int		 kf_names(int, StringList *);
#endif

#ifdef FACTS_H
int		 kfacts_emit(struct facts_out *, struct kfacts *);
void		 kfacts_record(void *, const struct facts_template *,
		    const struct facts_value *);
#endif

#endif /* KFACTS_H */
