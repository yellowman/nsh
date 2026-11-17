/*
 * Unit tests for stringlist.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../stringlist.h"
#include "test.h"

static void
test_add_and_grow(void)
{
	StringList *sl = sl_init();
	char buf[16];
	size_t i;

	CHECK(sl != NULL && sl->sl_cur == 0);
	/* well past the 20-entry chunk, so the list grows several times */
	for (i = 0; i < 100; i++) {
		snprintf(buf, sizeof(buf), "s%zu", i);
		sl_add(sl, strdup(buf));
	}
	CHECK(sl->sl_cur == 100);
	CHECK(sl->sl_max > sl->sl_cur);
	CHECK_STR(sl->sl_str[0], "s0");
	CHECK_STR(sl->sl_str[99], "s99");
	sl_free(sl, 1);
	sl_free(NULL, 1);	/* harmless */
}

static void
test_makestr(void)
{
	StringList *sl = sl_init();
	char *s;

	CHECK(sl_makestr(sl, ",") == NULL);	/* empty list */

	sl_add(sl, "a");
	s = sl_makestr(sl, ", ");
	CHECK_STR(s, "a");
	free(s);

	sl_add(sl, "bb");
	sl_add(sl, "ccc");
	s = sl_makestr(sl, ", ");
	CHECK_STR(s, "a, bb, ccc");
	free(s);

	s = sl_makestr(sl, "");
	CHECK_STR(s, "abbccc");
	free(s);
	sl_free(sl, 0);
}

int
main(void)
{
	RUN(test_add_and_grow);
	RUN(test_makestr);
	DONE();
}
