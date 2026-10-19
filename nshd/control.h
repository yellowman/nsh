/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

/* a client of a socket, and who it is */
struct ctl_conn {
	TAILQ_ENTRY(ctl_conn)	 entry;
	struct imsgev		 iev;
	uint32_t		 id;
	uid_t			 uid;
	gid_t			 gid;
	int			 pending;	/* a request not answered */
};

int	control_init(const char *, mode_t, gid_t);
int	control_listen(int, int (*)(struct ctl_conn *, struct imsg *),
	    void (*)(struct ctl_conn *));
int	control_reply(uint32_t, uint32_t, const void *, size_t);
struct ctl_conn	*control_connbyid(uint32_t);
