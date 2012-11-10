/*
 * A clean way to represent IPv4/IPv6 addresses for routines which purport to
 * handle either, inspiration from mrtd
 */
#ifndef _IP_T_
#define _IP_T_
#endif
typedef struct _ip_t {
	u_short family;		/* AF_INET | AF_INET6 */
	int bitlen;		/* bits */
	int ref_count;          /* reference count */
	union {
		struct in_addr in;
		struct in6_addr in6;
	} addr;
} ip_t;

