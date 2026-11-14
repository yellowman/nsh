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
 * frontend: one client of the read-write socket, its session. parent
 * accepts the client, and starts a frontend for it with its pipe to
 * config as fd 3 and the client's socket as fd 4, which only this
 * frontend has. What the client sends goes to config, on their pipe;
 * config's answers go back to the client, with the notices config sends
 * unasked, and config learns each time the client has read all it was
 * sent. frontend checks that a message is one a client (or config) may
 * send, and is whole. config knows whose session this is by the pipe it
 * comes on, so frontend cannot speak for another session.
 *
 * frontend reads the lines its client sends, a LINE's and a STAGE's,
 * with nsh's command tables (cmdline_edits()), in the mode config last
 * said the session is in, and sends config their edits: each command's
 * row, and the values its words parse to. config reads no word a client
 * typed; it checks the edits and runs them on the candidate. A line
 * that is none of the candidate's goes no further: frontend answers it
 * itself, with what its reading printed. A stage's line that is none is
 * answered where the stage reaches it, as config says it has; the lines
 * after it are not read. frontend parses a show's words and an
 * operation's the same way, into what the show asks and into the
 * operation's row and values, and answers itself one that is neither.
 * A client that completes lines itself asks for nsh's command tables:
 * frontend has them, and sends them once config says the session may
 * ask. frontend holds no candidate, and has only what config sends its
 * own client.
 *
 * When the client goes, frontend ends; config finds its pipe closed,
 * and parent tells system. When config closes its pipe, frontend ends
 * too.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>

#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"
#include "log.h"
#include "nshd.h"
#include "internal.h"
#include "control.h"
#include "facts.h"
#include "args.h"
#include "answer.h"

static uint32_t		 client;	/* the client's id, in control.c */
static uid_t		 web_uid;	/* NSHD_WEB_USER's uid */
static int		 web_user;	/* NSHD_WEB_USER exists */
static struct nshd_context ctx;		/* the session's mode, as config last
					   said it */

/*
 * The stage the client waits on: the line that enters its mode and the
 * lines of its text that were read, for the answers that name them
 */
static struct {
	char	 head[NSHD_LINE];
	char	 text[NSHD_TEXT + 1];	/* each line, ending in a NUL */
	int	 n;			/* the lines read: head is the first */
	int	 refused;		/* the last of them is none */
	int	 seen;			/* answers passed on */
} stage;

/* a client's request, as config takes it */
union frontend_request {
	struct nshd_show	 show;
	struct nshd_configure	 cf;
	struct nshd_line	 line;
	struct nshd_stage	 stage;
	struct nshd_commit	 commit;
	struct nshd_rollback	 rollback;
	struct nshd_op		 op;
	struct nshd_load	 load;
	struct nshd_rules	 rules;
	struct nshd_login	 login;
	struct nshd_watch	 watch;
	struct nshd_terminal	 terminal;
};

static void	frontend_dispatch_config(int, short, void *);
static void	frontend_answer(struct ctl_conn *, int32_t, int);
static void	frontend_show(struct ctl_conn *, struct nshd_show *);
static void	frontend_op(struct ctl_conn *, struct nshd_op *);
static void	frontend_commands(struct ctl_conn *, struct imsg *);
static void	frontend_units(void *, const void *, size_t);
static void	frontend_line(struct ctl_conn *, struct nshd_line *);
static void	frontend_stage(struct ctl_conn *, struct nshd_stage *);
static int	frontend_read(FILE *, char *, char *, int);
static void	frontend_edits(struct ctl_conn *, struct nshd_edits *,
		    char *, size_t);
static void	frontend_staged(struct ctl_conn *, struct nshd_staged *);
static int	frontend_client(struct ctl_conn *, struct imsg *);
static void	frontend_gone(struct ctl_conn *);
static int	frontend_written(struct ctl_conn *);
static ssize_t	frontend_whole(struct imsg *, union frontend_request *);

static struct link	 links[] = {
#define CONFIG		0
	{ PROC_CONFIG,	 frontend_dispatch_config },
};

void
frontend(int d, int v)
{
	struct passwd	*pw;

	child_start("frontend", d, v);
	if ((pw = getpwnam(NSHD_WEB_USER)) != NULL) {
		web_uid = pw->pw_uid;
		web_user = 1;
	}
	/* what reading a line prints is the client's */
	capture_stdout();
	privdrop(PROC_FRONTEND);

	/* a terminal's pty comes from config, to go to the client */
	if ((links[CONFIG].iev = imsgev_new(3, frontend_dispatch_config,
	    1)) == NULL)
		fatal(NULL);
	if ((client = control_one(4, frontend_client, frontend_gone,
	    frontend_written)) == 0)
		exit(1);
	/*
	 * Before the client's first message: only what it has, and the
	 * ptys it passes on. It may signal only its own process group,
	 * which parent made its own
	 */
	if (pledge("stdio recvfd sendfd", NULL) == -1)
		fatal("pledge");
	event_dispatch();
	exit(0);
}

/* config's answers, to the client */
static void
frontend_dispatch_config(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct ctl_conn		*c;
	struct nshd_staged	 sd;
	struct imsg		 imsg;
	struct ibuf		 b;
	uint32_t		 type;
	int			 n, pty;

	if (imsgev_io(iev, event) == -1) {
		link_broken(&links[CONFIG], "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(&links[CONFIG], "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_CTL_STAGED:
			/* a stage's line, which frontend names */
			if (imsg_get_data(&imsg, &sd, sizeof(sd)) == -1) {
				imsg_free(&imsg);
				link_broken(&links[CONFIG], "sent a line's "
				    "answer not whole");
				return;
			}
			if ((c = control_connbyid(client)) != NULL)
				frontend_staged(c, &sd);
			break;
		case IMSG_CTL_CONTEXT:
			/* the mode the client's next line is read in */
			if (imsg_get_data(&imsg, &ctx, sizeof(ctx)) == -1) {
				imsg_free(&imsg);
				link_broken(&links[CONFIG], "sent a context "
				    "not whole");
				return;
			}
			ctx.ifname[sizeof(ctx.ifname) - 1] = '\0';
			if (control_reply(client, type, &ctx,
			    sizeof(ctx)) == -1)
				control_drop(client);
			break;
		case IMSG_CTL_RESULT:
			/* the command tables, which config allowed */
			if ((c = control_connbyid(client)) != NULL &&
			    c->pending == IMSG_CTL_COMMANDS) {
				frontend_commands(c, &imsg);
				break;
			}
			/* FALLTHROUGH */
		case IMSG_CTL_HELLO:
			/* the request's end, and its stage's */
			if ((c = control_connbyid(client)) != NULL)
				c->pending = 0;
			printed_text(NULL, IMSG_CTL_OUTPUT, 0, 0);
			memset(&stage, 0, sizeof(stage));
			/* FALLTHROUGH */
		case IMSG_CTL_OUTPUT:
		case IMSG_CTL_FACTS:
		case IMSG_CTL_NOTICE:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (control_reply(client, type, ibuf_data(&b),
			    ibuf_size(&b)) == -1)
				control_drop(client);
			break;
		case IMSG_CTL_TERMINAL:
			/* a terminal's pty, before the request's end */
			if ((pty = imsg_get_fd(&imsg)) == -1 ||
			    imsg_get_len(&imsg) != 0) {
				imsg_free(&imsg);
				link_broken(&links[CONFIG], "sent a terminal "
				    "not whole");
				return;
			}
			if (control_pass(client, type, pty) == -1)
				control_drop(client);
			break;
		default:
			imsg_free(&imsg);
			link_broken(&links[CONFIG], "sent imsg %u, which it may not",
			    type);
			return;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/*
 * What the client sends, to config; -1 closes it. A client asks one
 * thing at a time, and waits for its answer.
 */
static int
frontend_client(struct ctl_conn *c, struct imsg *imsg)
{
	struct nshd_hello	 hello;
	struct nshd_show	 show;
	union frontend_request	 r;
	ssize_t			 len;

	if (c->pending)
		return (-1);
	c->pending = imsg_get_type(imsg);
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &hello, sizeof(hello)) == -1)
			return (-1);
		if (link_compose(&links[CONFIG], IMSG_CTL_HELLO, c->id, &hello,
		    sizeof(hello)) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &show, sizeof(show)) == -1 ||
		    memchr(show.words, '\0', sizeof(show.words)) == NULL)
			return (-1);
		frontend_show(c, &show);
		return (0);
	case IMSG_CTL_OP:
		if (frontend_whole(imsg, &r) == -1)
			return (-1);
		frontend_op(c, &r.op);
		explicit_bzero(&r, sizeof(r));
		return (0);
	case IMSG_CTL_COMMANDS:
	case IMSG_CTL_NAMES:
		/*
		 * completion's tables and names: these carry no data.
		 * config has the names, and says whether the session
		 * may have the tables (frontend_commands())
		 */
		if (imsg_get_len(imsg) != 0)
			return (-1);
		if (link_compose(&links[CONFIG], imsg_get_type(imsg), c->id,
		    NULL, 0) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_LINE:
		if (frontend_whole(imsg, &r) == -1)
			return (-1);
		frontend_line(c, &r.line);
		explicit_bzero(&r, sizeof(r));
		return (0);
	case IMSG_CTL_STAGE:
		if (frontend_whole(imsg, &r) == -1)
			return (-1);
		frontend_stage(c, &r.stage);
		explicit_bzero(&r, sizeof(r));
		return (0);
	case IMSG_CTL_LOGIN:
	case IMSG_CTL_TERMINAL:
		/* only the web configurator may send these */
		if (!web_user || c->uid != web_uid)
			return (-1);
		/* FALLTHROUGH */
	case IMSG_CTL_CONFIGURE:
	case IMSG_CTL_EXIT:
	case IMSG_CTL_COMMIT:
	case IMSG_CTL_ROLLBACK:
	case IMSG_CTL_LOAD:
	case IMSG_CTL_RULES:
	case IMSG_CTL_WATCH:
		if ((len = frontend_whole(imsg, &r)) == -1)
			return (-1);
		if (link_compose(&links[CONFIG], imsg_get_type(imsg), c->id,
		    len > 0 ? &r : NULL, len) == -1)
			fatal("%s", __func__);
		explicit_bzero(&r, sizeof(r));
		return (0);
	default:
		return (-1);
	}
}

/*
 * A request frontend answers itself, as it goes no further: what
 * reading it printed, the session's mode, if mode is set, and status
 */
static void
frontend_answer(struct ctl_conn *c, int32_t status, int mode)
{
	struct nshd_result	 res = { status };

	if (printed_text(&c->iev, IMSG_CTL_OUTPUT, 0, 0) == -1 ||
	    (mode && control_reply(c->id, IMSG_CTL_CONTEXT, &ctx,
	    sizeof(ctx)) == -1) || control_reply(c->id, IMSG_CTL_RESULT,
	    &res, sizeof(res)) == -1)
		control_drop(c->id);
	c->pending = 0;
}

/*
 * nsh's command tables, as facts, to the client, and then the result
 * with which config answered the request: config has checked that the
 * session may ask, and frontend has the tables. A result that refuses
 * is passed on as it is
 */
static void
frontend_commands(struct ctl_conn *c, struct imsg *imsg)
{
	struct units		 u = { frontend_units, c };
	struct nshd_result	 res;
	struct facts_out	 o;

	if (imsg_get_data(imsg, &res, sizeof(res)) == -1) {
		link_broken(&links[CONFIG], "sent a result not whole");
		return;
	}
	if (res.status == 0) {
		facts_out_init(&o, units_emit, &u);
		if (cmplt_facts(&o) == -1) {
			printf("%% nshd: the command tables could not be "
			    "sent\n");
			res.status = 1;
		}
		units_flush(&u);
	}
	frontend_answer(c, res.status, 0);
}

/* Facts units for the client arg, as one message. */
static void
frontend_units(void *arg, const void *buf, size_t len)
{
	struct ctl_conn	*c = arg;

	if (control_reply(c->id, IMSG_CTL_FACTS, buf, len) == -1)
		control_drop(c->id);
}

/*
 * A show: what its words ask, to config. One that asks for a rollback
 * no configuration kept has, or that nshd's system does not answer, is
 * answered here
 */
static void
frontend_show(struct ctl_conn *c, struct nshd_show *show)
{
	struct nshd_frontshow	 fs;
	const char		*errstr;
	char			 num[16], *p;

	memset(&fs, 0, sizeof(fs));
	if (strcmp(show->words, "candidate-config") == 0)
		fs.kind = NSHD_SHOW_CANDIDATE;
	else if (strcmp(show->words, "diff-config") == 0)
		fs.kind = NSHD_SHOW_DIFF;
	else if (strcmp(show->words, "running-config") == 0)
		fs.kind = NSHD_SHOW_RUNNING;
	else if (strcmp(show->words, "startup-config") == 0)
		fs.kind = NSHD_SHOW_STARTUP;
	else if (strcmp(show->words, "rollback") == 0)
		fs.kind = NSHD_SHOW_ROLLBACKS;
	else if (strncmp(show->words, "rollback ", 9) == 0) {
		/* rollback N, or rollback N diff, what N changed */
		strlcpy(num, show->words + 9, sizeof(num));
		fs.kind = NSHD_SHOW_ROLLBACK;
		if ((p = strchr(num, ' ')) != NULL && strcmp(p, " diff") == 0) {
			*p = '\0';
			fs.kind = NSHD_SHOW_ROLLDIFF;
		}
		fs.n = strtonum(num, 0, NSHD_ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			printf("%% rollback %s is %s\n", show->words + 9,
			    errstr);
			frontend_answer(c, 1, 0);
			return;
		}
	} else if (facts_answer_pack(show->words, &fs.ss) != 0) {
		printf("%% show %s: not answered by nshd\n", show->words);
		frontend_answer(c, NSHD_ELSEWHERE, 0);
		return;
	} else
		fs.kind = NSHD_SHOW_FACTS;
	if (link_compose(&links[CONFIG], IMSG_FRONT_SHOW, c->id, &fs,
	    sizeof(fs)) == -1)
		fatal("%s", __func__);
}

/*
 * An operation: its row of ops[] and the values nsh's words for it
 * parse to, to config, which passes it on to system. One whose words
 * are none an operation takes is answered here
 */
static void
frontend_op(struct ctl_conn *c, struct nshd_op *op)
{
	struct nshd_sysop	 so;
	struct argvals		 a;
	char			*w[NSHD_LINE / 2], *p = op->line;
	ssize_t			 len = -1;
	int			 n = 0, row = -1;

	memset(&so, 0, sizeof(so));
	while (n < (int)(sizeof(w) / sizeof(w[0])) &&
	    (w[n] = strsep(&p, " \t")) != NULL)
		if (*w[n] != '\0')
			n++;
	if (n == 0 || p != NULL)
		printf("%% nshd: an operation of no words, or too many\n");
	else if ((row = op_parse(n, w, &a, so.ifname, sizeof(so.ifname))) !=
	    -1)
		len = args_record(&ops[row], &a, so.values,
		    sizeof(so.values));
	if (len == -1)
		frontend_answer(c, 1, 0);
	else {
		so.rtable = op->rtable;
		so.row = row;
		so.set = a.set;
		so.len = len;
		if (link_compose(&links[CONFIG], IMSG_FRONT_OP, c->id, &so,
		    sizeof(so)) == -1)
			fatal("%s", __func__);
	}
	/* an operation can carry a PIN */
	explicit_bzero(&so, sizeof(so));
	explicit_bzero(&a, sizeof(a));
}

/*
 * A line: its edits, to config, which answers it. One that has none,
 * because it is none of the candidate's, is empty or only asked for
 * help, is answered here, with what reading it printed, the session's
 * mode, and a result. Outside configure, config says so
 */
static void
frontend_line(struct ctl_conn *c, struct nshd_line *l)
{
	struct nshd_edits	 ed;
	struct nshd_edline	 el;
	FILE			*f;
	char			*buf = NULL;
	size_t			 len = 0;
	int			 r = 0;

	memset(&ed, 0, sizeof(ed));
	if ((f = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	if (ctx.mode != 0) {
		memset(&el, 0, sizeof(el));
		fwrite(&el, sizeof(el), 1, f);
		r = cmdline_edits(l->line, ctx.ifname, ctx.bridge, f);
	}
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	if (ctx.mode != 0 && (r == -1 || len == sizeof(el)))
		frontend_answer(c, r == -1 ? -1 : 0, 1);
	else {
		if (ctx.mode != 0) {
			el.len = len - sizeof(el);
			memcpy(buf, &el, sizeof(el));
		}
		/* a line of configure terminal is named as it is committed */
		if (ctx.mode == NSHD_TERMINAL)
			strlcpy(ed.label, l->line, sizeof(ed.label));
		/* what reading it printed comes before what running it does */
		if (printed_text(&c->iev, IMSG_CTL_OUTPUT, 0, 0) == -1)
			control_drop(c->id);
		frontend_edits(c, &ed, buf, len);
	}
	free(buf);
}

/*
 * A stage: the line that enters its interface's mode, read in the
 * session's mode, then the lines of its text, read in that interface's,
 * to config, which runs them and answers each. The first line that is
 * none of the candidate's is sent as refused, and what reading it
 * printed waits here for config's answer to it (frontend_staged()); the
 * lines after it are not read, as none would run
 */
static void
frontend_stage(struct ctl_conn *c, struct nshd_stage *sg)
{
	struct nshd_edits	 ed;
	FILE			*f;
	char			 text[NSHD_TEXT + 1];
	char			*buf = NULL, *l, *next, *to = stage.text;
	size_t			 len = 0;

	memset(&ed, 0, sizeof(ed));
	memset(&stage, 0, sizeof(stage));
	ed.stage = 1;
	strlcpy(ed.ifname, sg->ifname, sizeof(ed.ifname));
	if ((f = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	if (ctx.mode != 0 && ctx.mode != NSHD_TERMINAL) {
		snprintf(stage.head, sizeof(stage.head), "%s %s",
		    sg->bridge ? "bridge" : "interface", sg->ifname);
		stage.n = 1;
		stage.refused = frontend_read(f, stage.head, ctx.ifname,
		    ctx.bridge) == -1;
		memcpy(text, sg->text, sg->len);
		text[sg->len] = '\0';
		for (l = text; !stage.refused && l != NULL; l = next) {
			if ((next = strchr(l, '\n')) != NULL)
				*next++ = '\0';
			if (*l == '\0')
				continue;
			to += strlcpy(to, l, sizeof(stage.text) -
			    (to - stage.text)) + 1;
			stage.n++;
			stage.refused = frontend_read(f, l, sg->ifname,
			    sg->bridge) == -1;
		}
	}
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	/* what reading the refused line printed waits for its answer */
	if (!stage.refused && printed_text(&c->iev, IMSG_CTL_OUTPUT, 0,
	    0) == -1)
		control_drop(c->id);
	frontend_edits(c, &ed, buf, len);
	explicit_bzero(text, sizeof(text));
	free(buf);
}

/*
 * text, a line read into f as a stage's, in the mode of interface ifn,
 * or at the top level if that is "": -1 if refused, which f says
 */
static int
frontend_read(FILE *f, char *text, char *ifn, int isbridge)
{
	struct nshd_edline	 el;
	FILE			*m;
	char			*buf = NULL;
	size_t			 len = 0;
	int			 r;

	if ((m = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	r = cmdline_edits(text, ifn, isbridge, m);
	if (fclose(m) == EOF)
		fatal("%s", __func__);
	memset(&el, 0, sizeof(el));
	el.refused = r == -1;
	el.len = r == -1 ? 0 : len;
	fwrite(&el, sizeof(el), 1, f);
	fwrite(buf, 1, el.len, f);
	free(buf);
	return (r);
}

/* a request's lines, buf's len bytes, to config, in as many parts as fit */
static void
frontend_edits(struct ctl_conn *c, struct nshd_edits *ed, char *buf,
    size_t len)
{
	size_t	 n;

	do {
		n = len < sizeof(ed->bytes) ? len : sizeof(ed->bytes);
		memcpy(ed->bytes, buf, n);
		ed->len = n;
		buf += n;
		len -= n;
		ed->last = len == 0;
		if (link_compose(&links[CONFIG], IMSG_FRONT_EDITS, c->id, ed,
		    sizeof(*ed)) == -1)
			fatal("%s", __func__);
	} while (len > 0);
	explicit_bzero(ed, sizeof(*ed));
}

/*
 * config's answer to a line of the stage, to the client, with the line
 * it is for, by its place: config names only the exit it adds. Before
 * the answer to the line refused here goes what reading it printed
 */
static void
frontend_staged(struct ctl_conn *c, struct nshd_staged *sd)
{
	char	*l;
	int	 i;

	sd->line[sizeof(sd->line) - 1] = '\0';
	if (sd->line[0] == '\0' && stage.seen < stage.n) {
		l = stage.head;
		for (i = 1; i <= stage.seen; i++)
			l = i == 1 ? stage.text : l + strlen(l) + 1;
		strlcpy(sd->line, l, sizeof(sd->line));
		if (++stage.seen == stage.n && stage.refused &&
		    printed_text(&c->iev, IMSG_CTL_OUTPUT, 0, 0) == -1) {
			control_drop(c->id);
			return;
		}
	}
	if (control_reply(c->id, IMSG_CTL_STAGED, sd, sizeof(*sd)) == -1)
		control_drop(c->id);
}

/* the client gone: frontend ends, and config and system drop the session */
static void
frontend_gone(struct ctl_conn *c)
{
	exit(0);
}

/* the client has read all it was sent, so system may stream it more */
static int
frontend_written(struct ctl_conn *c)
{
	if (imsgbuf_queuelen(&c->iev.ibuf) == 0 &&
	    link_compose(&links[CONFIG], IMSG_CTL_READ, c->id, NULL, 0) == -1)
		fatal("%s", __func__);
	return (0);
}

/*
 * A client's request other than hello, if it is whole, into r as config
 * takes it: its length, or -1
 */
static ssize_t
frontend_whole(struct imsg *imsg, union frontend_request *r)
{
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &r->show, sizeof(r->show)) == -1 ||
		    memchr(r->show.words, '\0', sizeof(r->show.words)) == NULL)
			return (-1);
		return (sizeof(r->show));
	case IMSG_CTL_CONFIGURE:
		if (imsg_get_data(imsg, &r->cf, sizeof(r->cf)) == -1)
			return (-1);
		return (sizeof(r->cf));
	case IMSG_CTL_LINE:
		if (imsg_get_data(imsg, &r->line, sizeof(r->line)) == -1 ||
		    memchr(r->line.line, '\0', sizeof(r->line.line)) == NULL)
			return (-1);
		return (sizeof(r->line));
	case IMSG_CTL_STAGE:
		if (imsg_get_data(imsg, &r->stage, sizeof(r->stage)) == -1 ||
		    (r->stage.bridge != 0 && r->stage.bridge != 1) ||
		    r->stage.ifname[0] == '\0' ||
		    memchr(r->stage.ifname, '\0',
		    sizeof(r->stage.ifname)) == NULL ||
		    r->stage.len < 0 || r->stage.len > NSHD_TEXT ||
		    memchr(r->stage.text, '\0', r->stage.len) != NULL)
			return (-1);
		return (sizeof(r->stage));
	case IMSG_CTL_EXIT:
		return (imsg_get_len(imsg) == 0 ? 0 : -1);
	case IMSG_CTL_COMMIT:
		if (imsg_get_data(imsg, &r->commit, sizeof(r->commit)) == -1 ||
		    memchr(r->commit.comment, '\0',
		    sizeof(r->commit.comment)) == NULL)
			return (-1);
		return (sizeof(r->commit));
	case IMSG_CTL_ROLLBACK:
		if (imsg_get_data(imsg, &r->rollback,
		    sizeof(r->rollback)) == -1)
			return (-1);
		return (sizeof(r->rollback));
	case IMSG_CTL_OP:
		if (imsg_get_data(imsg, &r->op, sizeof(r->op)) == -1 ||
		    memchr(r->op.line, '\0', sizeof(r->op.line)) == NULL)
			return (-1);
		return (sizeof(r->op));
	case IMSG_CTL_LOAD:
		if (imsg_get_data(imsg, &r->load, sizeof(r->load)) == -1 ||
		    (r->load.last != 0 && r->load.last != 1) ||
		    r->load.len < 0 || r->load.len > NSHD_TEXT ||
		    memchr(r->load.comment, '\0',
		    sizeof(r->load.comment)) == NULL)
			return (-1);
		return (sizeof(r->load));
	case IMSG_CTL_RULES:
		if (imsg_get_data(imsg, &r->rules, sizeof(r->rules)) == -1 ||
		    (r->rules.set != 0 && r->rules.set != 1) ||
		    (r->rules.last != 0 && r->rules.last != 1) ||
		    r->rules.len < 0 || r->rules.len > NSHD_TEXT ||
		    memchr(r->rules.daemon, '\0',
		    sizeof(r->rules.daemon)) == NULL)
			return (-1);
		return (sizeof(r->rules));
	case IMSG_CTL_LOGIN:
		if (imsg_get_data(imsg, &r->login, sizeof(r->login)) == -1 ||
		    memchr(r->login.name, '\0', sizeof(r->login.name)) == NULL ||
		    memchr(r->login.password, '\0',
		    sizeof(r->login.password)) == NULL)
			return (-1);
		return (sizeof(r->login));
	case IMSG_CTL_WATCH:
		if (imsg_get_data(imsg, &r->watch, sizeof(r->watch)) == -1)
			return (-1);
		return (sizeof(r->watch));
	case IMSG_CTL_TERMINAL:
		if (imsg_get_data(imsg, &r->terminal,
		    sizeof(r->terminal)) == -1 ||
		    r->terminal.rows < 1 || r->terminal.rows > NSHD_TERMSIZE ||
		    r->terminal.cols < 1 || r->terminal.cols > NSHD_TERMSIZE)
			return (-1);
		return (sizeof(r->terminal));
	}
	return (-1);
}
