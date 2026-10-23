/*
 * Unit tests for conftree.c: reading, writing, comparing and editing
 * configuration trees, and the candidate journal.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../conftree.h"
#include "test.h"

#define TMPCONF	"t_conftree.tmp"

/* A minimal grammar: interfaces and daemons take lines, rtables nest */
static int
t_mode(char *s)
{
	if (strncmp(s, "rtable ", 7) == 0)
		return CT_NESTED;
	if (strncmp(s, "interface ", 10) == 0 ||
	    strncmp(s, "bridge ", 7) == 0 ||
	    strstr(s, " rules") != NULL)
		return CT_LINES;
	return CT_LEAF;
}

static int
t_ordered(char *s)
{
	return strstr(s, " rules") != NULL;
}

static struct cnode *
parse(const char *text)
{
	FILE *f;

	if ((f = fopen(TMPCONF, "w")) == NULL)
		return NULL;
	fputs(text, f);
	fclose(f);
	return conftree_read(TMPCONF, t_mode, t_ordered);
}

/* Write a tree and read it back */
static struct cnode *
roundtrip(struct cnode *t)
{
	FILE *f;

	if ((f = fopen(TMPCONF, "w")) == NULL)
		return NULL;
	if (conftree_write(f, t) == -1) {
		fclose(f);
		return NULL;
	}
	fclose(f);
	return conftree_read(TMPCONF, t_mode, t_ordered);
}

static const char *base =
    "# a comment\n"
    "hostname gw1\n"
    "interface em0\n"
    " description uplink\n"
    " inet 192.0.2.1/24\n"
    " mtu 1500\n"
    "!\n"
    "\n"
    "interface em1\n"
    " inet 198.51.100.1/24\n"
    "!\n"
    "pf rules\n"
    " block all\n"
    " pass out\n"
    "!\n"
    "rtable 1\n"
    " interface vlan10\n"
    "  inet 10.0.0.1/24\n"
    " !\n"
    "!\n";

static void
test_read(void)
{
	struct cnode *t = parse(base);

	CHECK(t != NULL);
	if (t == NULL)
		return;
	CHECK_STR(conftree_stmt(t, 0), "hostname gw1");
	CHECK_STR(conftree_stmt(t, 1), "interface em0");
	CHECK_STR(conftree_stmt(t, 2), "interface em1");
	CHECK_STR(conftree_stmt(t, 3), "pf rules");
	CHECK_STR(conftree_stmt(t, 4), "rtable 1");
	CHECK(conftree_stmt(t, 5) == NULL);	/* comment and blank skipped */

	CHECK_STR(conftree_line(t, "interface em0", "mtu", 0), "mtu 1500");
	CHECK_STR(conftree_line(t, "interface em0", NULL, 0),
	    "description uplink");
	CHECK_STR(conftree_line(t, "pf rules", NULL, 1), "pass out");
	CHECK_STR(conftree_line(t, "rtable 1\ninterface vlan10", "inet", 0),
	    "inet 10.0.0.1/24");
	CHECK(conftree_has(t, "rtable 1\ninterface vlan10"));
	CHECK(!conftree_has(t, "interface em9"));
	conftree_free(t);
}

static void
test_orphan_lines_skipped(void)
{
	/* indented lines after a leaf statement or a '!' belong nowhere */
	struct cnode *t = parse(
	    "hostname gw1\n"
	    " stray line\n"
	    "interface em0\n"
	    " mtu 1500\n"
	    "!\n"
	    " another stray\n");

	CHECK(t != NULL);
	if (t == NULL)
		return;
	CHECK(conftree_stmt(t, 2) == NULL);
	CHECK_STR(conftree_line(t, "interface em0", NULL, 0), "mtu 1500");
	CHECK(conftree_line(t, "interface em0", NULL, 1) == NULL);
	conftree_free(t);
}

static void
test_roundtrip(void)
{
	struct cnode *t = parse(base), *u;

	CHECK(t != NULL);
	if (t == NULL)
		return;
	u = roundtrip(t);
	CHECK(u != NULL);
	if (u != NULL) {
		CHECK(conftree_compare(NULL, t, u) == 0);
		conftree_free(u);
	}
	conftree_free(t);
}

static void
test_long_line_roundtrip(void)
{
	/* conftree reads with getline(), so long rules lines survive */
	char *rule, *text;
	size_t len = 4000;
	struct cnode *t, *u;

	rule = malloc(len + 1);
	text = malloc(len + 64);
	if (rule == NULL || text == NULL)
		return;
	memset(rule, 'x', len);
	memcpy(rule, "table <big> {", 13);
	rule[len - 1] = '}';
	rule[len] = '\0';
	snprintf(text, len + 64, "pf rules\n %s\n!\n", rule);

	t = parse(text);
	CHECK(t != NULL);
	if (t != NULL) {
		CHECK_STR(conftree_line(t, "pf rules", NULL, 0), rule);
		u = roundtrip(t);
		CHECK(u != NULL && conftree_compare(NULL, t, u) == 0);
		conftree_free(u);
		conftree_free(t);
	}
	free(rule);
	free(text);
}

static void
test_compare_sets_and_sequences(void)
{
	struct cnode *a, *b;

	/* lines in an interface block are a set: order does not matter */
	a = parse("interface em0\n mtu 1500\n description x\n!\n");
	b = parse("interface em0\n description x\n mtu 1500\n!\n");
	CHECK(a != NULL && b != NULL);
	if (a && b)
		CHECK(conftree_compare(NULL, a, b) == 0);
	conftree_free(a);
	conftree_free(b);

	/* a changed line is one removal and one addition */
	a = parse("interface em0\n mtu 1500\n!\n");
	b = parse("interface em0\n mtu 9000\n!\n");
	if (a && b)
		CHECK(conftree_compare(NULL, a, b) == 2);
	conftree_free(a);
	conftree_free(b);

	/* rules are a sequence: reordering them is a difference */
	a = parse("pf rules\n block all\n pass out\n!\n");
	b = parse("pf rules\n pass out\n block all\n!\n");
	if (a && b)
		CHECK(conftree_compare(NULL, a, b) > 0);
	conftree_free(a);
	conftree_free(b);

	/* top-level statement order does not matter */
	a = parse("hostname gw1\ninterface em0\n mtu 1500\n!\n");
	b = parse("interface em0\n mtu 1500\n!\nhostname gw1\n");
	if (a && b)
		CHECK(conftree_compare(NULL, a, b) == 0);
	conftree_free(a);
	conftree_free(b);
}

static void
test_edit_set_unset(void)
{
	struct cnode *t = parse(base);

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	CHECK(conftree_edit(t, CE_SET, "interface em0", "mtu 9000", 1) ==
	    CE_CHANGED);
	CHECK_STR(conftree_line(t, "interface em0", "mtu", 0), "mtu 9000");
	CHECK(conftree_line(t, "interface em0", "mtu", 1) == NULL);

	/* setting the same value again is a no-op */
	CHECK(conftree_edit(t, CE_SET, "interface em0", "mtu 9000", 1) ==
	    CE_NOOP);

	/* "no mtu" has the same key as "mtu" */
	CHECK(conftree_edit(t, CE_UNSET, "interface em0", "no mtu", 1) ==
	    CE_CHANGED);
	CHECK(conftree_line(t, "interface em0", "mtu", 0) == NULL);
	CHECK(conftree_edit(t, CE_UNSET, "interface em0", "no mtu", 1) ==
	    CE_NOOP);

	/* CK_ADDR: the prefix length is not part of the key */
	CHECK(conftree_edit(t, CE_SET, "interface em0",
	    "inet 192.0.2.1/25", 2 | CK_ADDR) == CE_CHANGED);
	CHECK_STR(conftree_line(t, "interface em0", "inet", 0),
	    "inet 192.0.2.1/25");
	CHECK(conftree_line(t, "interface em0", "inet", 1) == NULL);
	CHECK(conftree_haskey(t, "interface em0", "inet 192.0.2.1/32",
	    2 | CK_ADDR));
	CHECK(!conftree_haskey(t, "interface em0", "inet 192.0.2.9/24",
	    2 | CK_ADDR));

	/* setting a line under a missing block creates the block */
	CHECK(conftree_edit(t, CE_SET, "interface em5", "mtu 1400", 1) ==
	    CE_CHANGED);
	CHECK(conftree_has(t, "interface em5"));

	/* unsetting under a missing block does not create it */
	CHECK(conftree_edit(t, CE_UNSET, "interface em6", "mtu", 1) ==
	    CE_NOOP);
	CHECK(!conftree_has(t, "interface em6"));
	conftree_free(t);
}

static void
test_edit_add_del_list(void)
{
	struct cnode *t = parse("bridge bridge0\n member em0\n!\n");

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	CHECK(conftree_edit(t, CE_ADD, "bridge bridge0", "stp em0", 0) ==
	    CE_CHANGED);
	CHECK(conftree_edit(t, CE_ADD, "bridge bridge0", "stp em0", 0) ==
	    CE_NOOP);
	CHECK(conftree_edit(t, CE_DEL, "bridge bridge0", "stp em0", 0) ==
	    CE_CHANGED);
	CHECK(conftree_line(t, "bridge bridge0", "stp", 0) == NULL);

	/* list values join and leave one line, each value once */
	CHECK(conftree_edit(t, CE_LISTADD, "bridge bridge0",
	    "member em1 em2", 0) == CE_CHANGED);
	CHECK_STR(conftree_line(t, "bridge bridge0", "member", 0),
	    "member em0 em1 em2");
	CHECK(conftree_edit(t, CE_LISTADD, "bridge bridge0",
	    "member em1", 0) == CE_NOOP);
	CHECK(conftree_edit(t, CE_LISTDEL, "bridge bridge0",
	    "member em0 em2", 0) == CE_CHANGED);
	CHECK_STR(conftree_line(t, "bridge bridge0", "member", 0),
	    "member em1");
	/* removing the last value removes the line */
	CHECK(conftree_edit(t, CE_LISTDEL, "bridge bridge0",
	    "member em1", 0) == CE_CHANGED);
	CHECK(conftree_line(t, "bridge bridge0", "member", 0) == NULL);
	conftree_free(t);
}

static void
test_edit_blocks(void)
{
	struct cnode *t = parse("interface em0\n mtu 1500\n!\n");

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	CHECK(conftree_edit(t, CE_BLOCK, NULL, "interface em1", 0) ==
	    CE_CHANGED);
	CHECK(conftree_edit(t, CE_BLOCK, NULL, "interface em1", 0) ==
	    CE_NOOP);
	CHECK(conftree_edit(t, CE_RENAME, "interface em0", "interface em2",
	    0) == CE_CHANGED);
	CHECK(!conftree_has(t, "interface em0"));
	CHECK_STR(conftree_line(t, "interface em2", "mtu", 0), "mtu 1500");
	/* renaming onto an existing statement is refused */
	CHECK(conftree_edit(t, CE_RENAME, "interface em2", "interface em1",
	    0) == CE_NOOP);
	CHECK(conftree_edit(t, CE_NOBLOCK, NULL, "interface em2", 0) ==
	    CE_CHANGED);
	CHECK(!conftree_has(t, "interface em2"));

	/* ordered blocks keep the sequence they were given */
	CHECK(conftree_edit(t, CE_SEQ, "pf rules", "block all", 0) ==
	    CE_CHANGED);
	CHECK(conftree_edit(t, CE_SEQ, "pf rules", "pass out", 0) ==
	    CE_CHANGED);
	CHECK_STR(conftree_line(t, "pf rules", NULL, 0), "block all");
	CHECK_STR(conftree_line(t, "pf rules", NULL, 1), "pass out");
	conftree_free(t);
}

/*
 * The tree must refuse any line that would not read back as the same
 * single line: an embedded newline would otherwise add a statement to
 * the saved configuration.
 */
static void
test_edit_rejects_unstorable(void)
{
	struct cnode *t = parse("interface em0\n mtu 1500\n!\n");

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	CHECK(conftree_edit(t, CE_SET, "interface em0",
	    "description a\nhostname evil", 1) == -1);
	CHECK(conftree_edit(t, CE_SET, "interface em0", "", 1) == -1);
	CHECK(conftree_edit(t, CE_SET, "interface em0", "   ", 1) == -1);
	CHECK(conftree_edit(t, CE_SET, "interface em0", " mtu 1", 1) == -1);
	CHECK(conftree_edit(t, CE_SET, "interface em0", "!", 1) == -1);
	CHECK(conftree_edit(t, CE_SET, "interface em0", "# x", 1) == -1);
	CHECK(conftree_edit(t, CE_BLOCK, NULL, "hostname a\nhostname b", 0) ==
	    -1);
	CHECK(conftree_edit(t, CE_SET, "!bad", "mtu 1", 1) == -1);
	CHECK(conftree_edit(t, CE_SEQ, "pf rules", "a\nb", 0) == -1);
	CHECK(conftree_edit(t, CE_SEQ, NULL, "block all", 0) == -1);
	/* nothing above changed the tree */
	CHECK_STR(conftree_line(t, "interface em0", NULL, 0), "mtu 1500");
	CHECK(conftree_line(t, "interface em0", NULL, 1) == NULL);
	CHECK(conftree_stmt(t, 1) == NULL);
	conftree_free(t);
}

static void
test_copy(void)
{
	struct cnode *t = parse(base), *c;

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	c = conftree_copy(t);
	CHECK(c != NULL);
	if (c != NULL) {
		CHECK(conftree_compare(NULL, t, c) == 0);
		/* the copy is deep */
		conftree_edit(c, CE_SET, "interface em0", "mtu 9000", 1);
		CHECK_STR(conftree_line(t, "interface em0", "mtu", 0),
		    "mtu 1500");
		CHECK(conftree_compare(NULL, t, c) == 2);
		conftree_free(c);
	}
	conftree_free(t);
}

static void
test_journal_replay(void)
{
	struct cnode *running, *newer;
	struct cjournal *j = cjournal_new();

	CHECK(j != NULL);
	if (j == NULL)
		return;
	running = parse("interface em0\n mtu 1500\n!\n");
	CHECK(cjournal_add(j, CE_SET, "interface em0", "mtu 9000", 1) == 0);
	CHECK(cjournal_add(j, CE_ADD, "interface em0", "description x", 0) ==
	    0);
	CHECK(cjournal_len(j) == 2);
	if (running != NULL) {
		CHECK(cjournal_replay(j, running) == 0);
		CHECK_STR(conftree_line(running, "interface em0", "mtu", 0),
		    "mtu 9000");
	}

	/* replaying on a newer running config keeps its other changes */
	newer = parse("interface em0\n mtu 1500\n inet 192.0.2.1/24\n!\n");
	if (newer != NULL) {
		CHECK(cjournal_replay(j, newer) == 0);
		CHECK_STR(conftree_line(newer, "interface em0", "mtu", 0),
		    "mtu 9000");
		CHECK_STR(conftree_line(newer, "interface em0", "inet", 0),
		    "inet 192.0.2.1/24");
		CHECK_STR(conftree_line(newer, "interface em0",
		    "description", 0), "description x");
	}

	/* a journal holding an unstorable line fails to replay */
	CHECK(cjournal_add(j, CE_SET, "interface em0", "a\nb", 1) == 0);
	if (newer != NULL)
		CHECK(cjournal_replay(j, newer) == -1);

	conftree_free(running);
	conftree_free(newer);
	cjournal_free(j);
}

static void
test_missing_file(void)
{
	remove(TMPCONF);
	CHECK(conftree_read(TMPCONF, t_mode, t_ordered) == NULL);
}

int
main(void)
{
	RUN(test_read);
	RUN(test_orphan_lines_skipped);
	RUN(test_roundtrip);
	RUN(test_long_line_roundtrip);
	RUN(test_compare_sets_and_sequences);
	RUN(test_edit_set_unset);
	RUN(test_edit_add_del_list);
	RUN(test_edit_blocks);
	RUN(test_edit_rejects_unstorable);
	RUN(test_copy);
	RUN(test_journal_replay);
	RUN(test_missing_file);
	remove(TMPCONF);
	DONE();
}
