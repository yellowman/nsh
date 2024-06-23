/*
 * Copyright (c) 2008-2009 Chris Cappuccio <chris@nmedia.net>
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

struct prot1 {
	char *name;
	char *help;
	char *args[32];
};

struct prot {
	char *name;
	struct prot1 *table;
};

#define BGPD_SOCKET_PATH "/var/run/bgpd.sock"
extern char bgpd_socket_path[PATH_MAX];
void init_bgpd_socket_path(int);
extern struct prot prots[];
int show_help(int, char **);
Command *getcmd(char *);
extern Menu showlist[];
void makeargv(void);
extern pid_t child;
extern int	nsh_setrtable(int);
extern void	sigalarm(int);
extern char hbuf[MAXHOSTNAMELEN];
extern char ifname[IFNAMSIZ];
int	help(int, char**);
