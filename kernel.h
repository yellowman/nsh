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
 * What the kernel does, read from its source (kernel.c, which
 * scripts/kernscan.pl makes)
 */

/* An interface cloner, and the interfaces it creates */
struct kcloner {
	const char *name;	/* "vlan" */
	int type;		/* the if_type it sets: IFT_ETHER */
	int bridge;		/* is_bridge() calls it a bridge */
	int flags;		/* the if_flags it sets: IFF_BROADCAST | ... */
	const u_long *ioctls;	/* the driver ioctls it takes, then 0 */
};

extern const char kernel_source[];	/* the source it was read from */

/* values the kernel checks or reports that no userland header defines */
extern const int kern_txpower_min, kern_txpower_max;
extern const int kern_bstp_port_admcost, kern_bstp_max_path_cost;
extern const struct kcloner kcloners[];
