/*
 * Unit tests for genget.c: the command-name matching every command
 * table lookup goes through.
 */

#include <stdio.h>
#include <string.h>

#include "test.h"

int isprefix(char *, char *);
char **genget(char *, char **, int);
int Ambiguous(void *);

struct ent {
	char *name;
	int id;
};

static struct ent table[] = {
	{ "hostname",	1 },
	{ "interface",	2 },
	{ "in",		3 },
	{ "show",	4 },
	{ "shell",	5 },
	{ "quit",	6 },
	{ 0,		0 }
};

static struct ent *
lookup(char *name)
{
	return (struct ent *)genget(name, (char **)table, sizeof(struct ent));
}

static void
test_isprefix(void)
{
	CHECK(isprefix("sh", "show") == 2);
	CHECK(isprefix("show", "show") == -4);
	CHECK(isprefix("SHOW", "show") == -4);	/* case-insensitive */
	CHECK(isprefix("Sh", "show") == 2);
	CHECK(isprefix("shows", "show") == 0);
	CHECK(isprefix("x", "show") == 0);
}

static void
test_genget(void)
{
	struct ent *e;

	e = lookup("quit");
	CHECK(e != NULL && !Ambiguous(e) && e->id == 6);

	e = lookup("q");			/* unique prefix */
	CHECK(e != NULL && !Ambiguous(e) && e->id == 6);

	e = lookup("in");			/* exact match beats a prefix */
	CHECK(e != NULL && !Ambiguous(e) && e->id == 3);

	e = lookup("int");
	CHECK(e != NULL && !Ambiguous(e) && e->id == 2);

	e = lookup("sh");			/* show or shell */
	CHECK(e != NULL && Ambiguous(e));

	e = lookup("she");
	CHECK(e != NULL && !Ambiguous(e) && e->id == 5);

	CHECK(lookup("nosuch") == NULL);
	CHECK(lookup(NULL) == NULL);
}

static void
test_empty_name(void)
{
	/*
	 * An empty argument ("" on the command line) is not a prefix of
	 * anything, but isprefix() calls it an exact match, so it selects
	 * the first entry of the table.
	 */
	KNOWN_BUG(lookup("") == NULL,
	    "empty name matches the first table entry (genget.c isprefix())");
}

int
main(void)
{
	RUN(test_isprefix);
	RUN(test_genget);
	RUN(test_empty_name);
	DONE();
}
