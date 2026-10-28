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
 * A session's state: each global a handler reads or writes and keeps
 * from one request to the next (globals.list's session class). Each is
 * named in an SGLOBAL table of the file that has it, and held by the
 * session while it is not running (session.c)
 */
struct sglobal {
	const char	*name;
	void		*addr;
	size_t		 size;
};
#define SGLOBAL(g)	{ #g, &(g), sizeof(g) }

struct session_state;
struct cnode;

/* What a commit runs, from session_plan(), in the parts nshd sends */
#define PLAN_EDITS	0	/* the script's edits, later the rollback's */
#define PLAN_BEFORE	1	/* the running configuration, as text */
#define PLAN_WANT	2	/* the candidate, as text */
#define PLAN_PARTS	3
#define PLAN_CLEARS	64	/* externs.h's MAXCLEARS */

/* a daemon's test of its rules, which system runs for a plan */
struct plan_test {
	char		 name[32];	/* the daemon */
	char		*label;		/* the line, and its block */
	char		*text;		/* the rules */
	size_t		 len;
};

struct plan {
	int		 same;		/* the candidate is the running one */
	char		*text[PLAN_PARTS];
	size_t		 len[PLAN_PARTS];
	struct {
		char	 name[32];
		int	 rtable;
		int	 keep;
	}		 clears[PLAN_CLEARS];	/* from the script */
	int		 nclears;
	struct plan_test *tests;	/* to run before the verdict */
	int		 ntests;
	int		 bad;		/* problems found, but not the tests' */
	int		 checking;	/* commit check */
	int		 boot;		/* boot plan: skip lines that are not
					   configuration (script_make()) */
	struct cnode	*was, *want;
};

extern int in_config;

struct session_state	*session_new(void);
void			 session_free(struct session_state *);
void			 session_enter(struct session_state *);
void			 session_leave(struct session_state *);
const struct sglobal	*session_global(size_t);
int			 session_running(char *, size_t);
struct cand_shared;
int			 session_configure(struct session_state *,
			    struct cand_shared *);
struct cand_shared	*cand_shared_new(void);
int			 cand_shared_renew(struct cand_shared *);
int			 cand_shared_changed(struct cand_shared *);
unsigned int		 cand_shared_edits(struct cand_shared *);
int			 cand_shared_write(struct cand_shared *, FILE *);
int			 cand_shared_read(struct cand_shared *, char *, size_t);
extern const char	*cand_held;
int			 session_line(struct session_state *, char *);
int			 session_rules(struct session_state *, char *, int, int,
			    char *, size_t);
/* nsh's command tables, sent as facts */
struct facts_out;
int			 cmplt_facts(struct facts_out *);
int			 session_exit(struct session_state *);
void			 session_mode(struct session_state *, int *, int *,
			    char *, size_t, int *);
int			 session_candidate(struct session_state *);
int			 session_diff(struct session_state *);
int			 session_plan(struct session_state *, int, int,
			    struct plan **);
void			 session_tested(struct plan *, int, int);
int			 session_verdict(struct plan *);
int			 session_verify(struct plan *, int);
int			 session_verify_back(struct plan *);
void			 plan_free(struct plan *);
int			 session_boot_plan(char *, size_t, struct plan **);
int			 session_boot_verify(struct plan *, int);
int			 session_renew(struct session_state *);
int			 session_changed(struct session_state *);
int			 session_load(struct session_state *, char *, size_t);
int			 session_rollback(struct session_state *, char *,
			    size_t, int);
