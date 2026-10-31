/*
 * Unit tests for makeargv.c: splitting the command line into margv[].
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"

/* defined in makeargv.c */
extern char line[1024];
extern char saveline[1024];
extern int margc;
extern char *margv[];
extern size_t cursor_argc;
void makeargv(void);

#define NARGS	(sizeof(line) / 2)

/* defined in main.c, which the tests do not link */
char *cursor_pos = NULL;

static void
parse(const char *s)
{
	snprintf(line, sizeof(line), "%s", s);
	cursor_pos = NULL;
	makeargv();
}

static void
test_words(void)
{
	parse("show interface em0");
	CHECK(margc == 3);
	CHECK_STR(margv[0], "show");
	CHECK_STR(margv[1], "interface");
	CHECK_STR(margv[2], "em0");
	CHECK(margv[3] == NULL);

	parse("   show\t\tip   route  ");
	CHECK(margc == 3);
	CHECK_STR(margv[0], "show");
	CHECK_STR(margv[1], "ip");
	CHECK_STR(margv[2], "route");
	CHECK(margv[margc] == NULL);
}

static void
test_empty(void)
{
	parse("");
	CHECK(margc == 0);
	CHECK(margv[0] == NULL);

	parse("    \t ");
	CHECK(margc == 0);
	CHECK(margv[0] == NULL);
}

static void
test_quoting(void)
{
	parse("description \"my uplink port\"");
	CHECK(margc == 2);
	CHECK_STR(margv[1], "my uplink port");

	parse("description 'it''s'");
	CHECK(margc == 2);
	CHECK_STR(margv[1], "its");

	parse("description \"say 'hi'\"");
	CHECK(margc == 2);
	CHECK_STR(margv[1], "say 'hi'");

	parse("a\\ b c");
	CHECK(margc == 2);
	CHECK_STR(margv[0], "a b");
	CHECK_STR(margv[1], "c");

	parse("x\"y z\"w");
	CHECK(margc == 1);
	CHECK_STR(margv[0], "xy zw");

	/* an unterminated quote runs to the end of the line */
	parse("description \"open ended");
	CHECK(margc == 2);
	CHECK_STR(margv[1], "open ended");

	/* a trailing backslash does not read past the line */
	parse("abc\\");
	CHECK(margc == 1);
	CHECK_STR(margv[0], "abc");
}

static void
test_shell_escape(void)
{
	parse("!ls -l /tmp");
	CHECK(margc == 4);
	CHECK_STR(margv[0], "!");
	CHECK_STR(margv[1], "ls");
	CHECK_STR(margv[3], "/tmp");
	CHECK_STR(saveline, "!ls -l /tmp");

	parse("!");
	CHECK(margc == 1);
	CHECK_STR(margv[0], "!");
}

/* "a a a ... a": n one-letter words in 2n - 1 characters */
static void
words(int n)
{
	int i;

	for (i = 0; i < n; i++) {
		line[2 * i] = 'a';
		line[2 * i + 1] = ' ';
	}
	line[2 * n - 1] = '\0';
	cursor_pos = NULL;
	makeargv();
}

static void
test_most_words(void)
{
	/* the most words margv[] can hold with its terminating NULL */
	words(NARGS - 1);
	CHECK(margc == (int)NARGS - 1);
	CHECK(margv[NARGS - 1] == NULL);
}

static void
test_too_many_words(void)
{
	pid_t pid;
	int status;

	/*
	 * A full line holds NARGS words, so makeargv() stores its
	 * terminating NULL at margv[NARGS], past the end of the array.
	 * Run it in a child, so the stray write cannot disturb the tests,
	 * and expect makeargv() to stop at NARGS - 1 words.
	 *
	 * The stray write lands on whichever global the linker put after
	 * margv[] (margc on some builds), so judge by margv[NARGS - 1],
	 * inside the array: NULL if makeargv() stopped in time, the
	 * NARGS'th word if it did not.
	 */
	fflush(stdout);
	if ((pid = fork()) == -1) {
		CHECK(pid != -1);
		return;
	}
	if (pid == 0) {
		words(NARGS);
		_exit(margv[NARGS - 1] == NULL ? 0 : 1);
	}
	if (waitpid(pid, &status, 0) == -1) {
		CHECK(0);
		return;
	}
	KNOWN_BUG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "a line of NARGS words overflows margv[] (makeargv.c makeargv())");
}

int
main(void)
{
	RUN(test_words);
	RUN(test_empty);
	RUN(test_quoting);
	RUN(test_shell_escape);
	RUN(test_most_words);
	RUN(test_too_many_words);
	DONE();
}
