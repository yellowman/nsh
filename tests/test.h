/*
 * A minimal unit test harness for the nsh regression tests.
 *
 * CHECK() records a failure and carries on, so one run reports every
 * broken expectation. KNOWN_BUG() marks a check that documents a bug
 * which is not fixed yet: it is reported as XFAIL while it fails and
 * as XPASS (and counted as a failure) once it starts passing, so the
 * test is promoted to a CHECK() when the fix lands.
 */

#ifndef NSH_TEST_H
#define NSH_TEST_H

#include <stdio.h>
#include <string.h>

static int t_fail, t_pass, t_xfail;

#define CHECK(cond) do {						\
	if (cond)							\
		t_pass++;						\
	else {								\
		t_fail++;						\
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);	\
	}								\
} while (0)

#define CHECK_STR(got, want) do {					\
	const char *g_ = (got), *w_ = (want);				\
	if (g_ != NULL && w_ != NULL && strcmp(g_, w_) == 0)		\
		t_pass++;						\
	else if (g_ == NULL && w_ == NULL)				\
		t_pass++;						\
	else {								\
		t_fail++;						\
		printf("FAIL %s:%d: %s: got \"%s\", want \"%s\"\n",	\
		    __FILE__, __LINE__, #got, g_ ? g_ : "(null)",	\
		    w_ ? w_ : "(null)");				\
	}								\
} while (0)

#define KNOWN_BUG(cond, why) do {					\
	if (cond) {							\
		t_fail++;						\
		printf("XPASS %s:%d: %s (%s) - promote to CHECK()\n",	\
		    __FILE__, __LINE__, #cond, why);			\
	} else {							\
		t_xfail++;						\
		printf("XFAIL %s:%d: %s\n", __FILE__, __LINE__, why);	\
	}								\
} while (0)

#define RUN(fn) do {							\
	printf("-- %s\n", #fn);						\
	fn();								\
} while (0)

#define DONE() do {							\
	printf("%d passed, %d failed, %d known bugs\n",			\
	    t_pass, t_fail, t_xfail);					\
	return t_fail ? 1 : 0;						\
} while (0)

#endif
