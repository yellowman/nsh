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
 * Facts: what a show finds, as records a client renders its own way.
 * A record's kind is described once, by a template: the kind's name,
 * and each field's name and type, with names for the bits of a flags
 * field or the values of an enum. A record is its template's id and
 * its values, in the template's order, any of them absent.
 *
 * Each template and each record is one unit, which fits in one imsg.
 * Templates are a reply's own: each reply sends a kind's template
 * before its first record of that kind, with ids from 0, and a reader
 * reads one reply, so what passes units on keeps nothing between
 * replies. Integers go in network byte order. A unit:
 *
 *	u8 FACTS_TEMPLATE, u16 id, string kind, u16 fields, and per field:
 *	    string name, u8 type, u8 naming, u16 names, and per name:
 *	    u64 value, string name
 *	u8 FACTS_RECORD, u16 id, and per field: u8 type (FACT_NONE when
 *	    absent) and its value
 *
 * A string is u16 length and its bytes, with no NUL. A value:
 *
 *	FACT_U64, FACT_I64	8 bytes
 *	FACT_STRING		a string
 *	FACT_ADDRESS		u8 family, u8 length, its bytes, u32 scope
 *	FACT_TIME		i64 seconds, u32 nanoseconds
 */

#ifndef FACTS_H
#define FACTS_H

#define FACTS_TEMPLATE	1
#define FACTS_RECORD	2

#define FACT_NONE	0	/* absent */
#define FACT_U64	1
#define FACT_I64	2
#define FACT_STRING	3
#define FACT_ADDRESS	4
#define FACT_TIME	5

#define FACT_PLAIN	0	/* no names */
#define FACT_BITS	1	/* names of bits */
#define FACT_VALUES	2	/* names of values */

#define FACT_INET	1
#define FACT_INET6	2
#define FACT_LINK	3

#define FACTS_UNIT	16000	/* a unit, at most: one imsg */
#define FACTS_KINDS	32	/* templates in one answer, at most */
#define FACTS_FIELDS	256	/* fields of a kind, at most */
#define FACTS_ADDRLEN	32	/* bytes of an address, at most */

struct facts_name {
	uint64_t		 value;
	const char		*name;
};

struct facts_field {
	const char		*name;
	uint8_t			 type;
	uint8_t			 naming;
	const struct facts_name	*names;
	size_t			 nnames;
};

struct facts_kind {
	const char		*name;
	const struct facts_field *fields;
	size_t			 nfields;
};

struct facts_address {
	uint8_t			 family;
	uint8_t			 len;
	uint8_t			 bytes[FACTS_ADDRLEN];
	uint32_t		 scope;
};

struct facts_value {
	uint8_t			 type;	/* FACT_NONE if absent */
	union {
		uint64_t	 u;
		int64_t		 i;
		struct {
			const char	*s;
			size_t		 len;
		}		 str;
		struct facts_address a;
		struct {
			int64_t		 sec;
			uint32_t	 nsec;
		}		 t;
	}			 v;
};

/* where an answer's units go, and which templates it has sent */
struct facts_out {
	void			(*emit)(void *, const void *, size_t);
	void			*arg;
	const struct facts_kind	*sent[FACTS_KINDS];
	size_t			 nsent;
};

/* a template as read */
struct facts_template {
	uint16_t		 id;
	char			*kind;
	size_t			 nfields;
	struct facts_tfield {
		char		*name;
		uint8_t		 type;
		uint8_t		 naming;
		size_t		 nnames;
		struct facts_tname {
			uint64_t value;
			char	*name;
		}		*names;
	}			*fields;
};

/* what reads an answer's units, and gets each record */
struct facts_in {
	void			(*record)(void *, const struct facts_template *,
				    const struct facts_value *);
	void			*arg;
	struct facts_template	*t[FACTS_KINDS];
};

void	facts_out_init(struct facts_out *, void (*)(void *, const void *,
	    size_t), void *);
int	facts_record(struct facts_out *, const struct facts_kind *,
	    const struct facts_value *);
void	facts_u64(struct facts_value *, uint64_t);
void	facts_i64(struct facts_value *, int64_t);
void	facts_string(struct facts_value *, const char *);
void	facts_time(struct facts_value *, int64_t, uint32_t);
void	facts_address(struct facts_value *, uint8_t, const void *, size_t,
	    uint32_t);

void	facts_in_init(struct facts_in *, void (*)(void *,
	    const struct facts_template *, const struct facts_value *), void *);
int	facts_read(struct facts_in *, const void *, size_t);
void	facts_in_free(struct facts_in *);
void	facts_bind(const struct facts_template *, const struct facts_kind *,
	    int *);
const struct facts_value *facts_get(const struct facts_value *, const int *,
	    size_t, uint8_t);
struct facts_value *facts_copy(const struct facts_template *,
	    const struct facts_value *);
void	facts_copy_free(const struct facts_template *, struct facts_value *);
char	*facts_strdup(const struct facts_value *);

#endif /* FACTS_H */
