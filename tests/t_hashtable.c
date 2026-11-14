/*
 * Unit tests for hashtable.c, which holds the session environment
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

struct hashtable;
struct hashtable *hashtable_alloc(void);
void hashtable_free(struct hashtable *);
int hashtable_add(struct hashtable *, void *, size_t, void *, size_t);
void *hashtable_get_keyptr(struct hashtable *, void *, size_t);
void *hashtable_get_value(struct hashtable *, void *, size_t);
int hashtable_remove(struct hashtable *, void **, void **, size_t *,
    void *, size_t);
int hashtable_contains(struct hashtable *, void *, size_t);
int hashtable_foreach(struct hashtable *,
    int (*)(void *, size_t, void *, size_t, void *), void *);
int hashtable_num_entries(struct hashtable *);

#define NKEYS	1000

static char *keys[NKEYS], *vals[NKEYS];

static int
count_cb(void *k, size_t ks, void *v, size_t vs, void *arg)
{
	(*(int *)arg)++;
	return 0;
}

static int
stop_cb(void *k, size_t ks, void *v, size_t vs, void *arg)
{
	return ++(*(int *)arg) == 3 ? 42 : 0;
}

static struct hashtable *add_during_walk_table;

static int
add_cb(void *k, size_t ks, void *v, size_t vs, void *arg)
{
	static char key[] = "added-during-walk";

	*(int *)arg = hashtable_add(add_during_walk_table, key,
	    sizeof(key), NULL, 0);
	return 1;
}

static void
test_add_get(void)
{
	struct hashtable *t = hashtable_alloc();
	char buf[32];
	int i, ok = 1;

	CHECK(t != NULL);
	if (t == NULL)
		return;
	/* enough entries to make the table grow past its 64 buckets */
	for (i = 0; i < NKEYS; i++) {
		snprintf(buf, sizeof(buf), "KEY%d", i);
		keys[i] = strdup(buf);
		snprintf(buf, sizeof(buf), "value%d", i);
		vals[i] = strdup(buf);
		if (hashtable_add(t, keys[i], strlen(keys[i]) + 1, vals[i],
		    strlen(vals[i]) + 1) != 0)
			ok = 0;
	}
	CHECK(ok);
	CHECK(hashtable_num_entries(t) == NKEYS);

	ok = 1;
	for (i = 0; i < NKEYS; i++) {
		snprintf(buf, sizeof(buf), "KEY%d", i);
		if (hashtable_get_value(t, buf, strlen(buf) + 1) != vals[i] ||
		    hashtable_get_keyptr(t, buf, strlen(buf) + 1) != keys[i])
			ok = 0;
	}
	CHECK(ok);
	CHECK(hashtable_contains(t, "KEY5", 5));
	CHECK(!hashtable_contains(t, "KEY5", 4));	/* keysize counts */
	CHECK(!hashtable_contains(t, "nosuch", 7));
	CHECK(hashtable_get_value(t, "nosuch", 7) == NULL);

	/* keys are unique */
	CHECK(hashtable_add(t, "KEY7", 5, NULL, 0) == -1);
	CHECK(hashtable_num_entries(t) == NKEYS);

	hashtable_free(t);
	for (i = 0; i < NKEYS; i++) {
		free(keys[i]);
		free(vals[i]);
	}
}

static void
test_remove(void)
{
	struct hashtable *t = hashtable_alloc();
	void *k, *v;
	size_t vs;

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	CHECK(hashtable_remove(t, &k, &v, &vs, "a", 2) == -1);	/* empty */
	CHECK(k == NULL && v == NULL && vs == 0);

	CHECK(hashtable_add(t, "a", 2, "1", 2) == 0);
	CHECK(hashtable_add(t, "b", 2, "2", 2) == 0);
	CHECK(hashtable_remove(t, &k, &v, &vs, "a", 2) == 0);
	CHECK_STR(k, "a");
	CHECK_STR(v, "1");
	CHECK(vs == 2);
	CHECK(!hashtable_contains(t, "a", 2));
	CHECK(hashtable_contains(t, "b", 2));
	CHECK(hashtable_num_entries(t) == 1);
	CHECK(hashtable_remove(t, NULL, NULL, NULL, "a", 2) == -1);
	CHECK(hashtable_remove(t, NULL, NULL, NULL, "b", 2) == 0);
	CHECK(hashtable_num_entries(t) == 0);
	hashtable_free(t);
}

static void
test_foreach(void)
{
	struct hashtable *t = hashtable_alloc();
	int n = 0, rv = 0;

	if (t == NULL) {
		CHECK(t != NULL);
		return;
	}
	hashtable_add(t, "a", 2, NULL, 0);
	hashtable_add(t, "b", 2, NULL, 0);
	hashtable_add(t, "c", 2, NULL, 0);
	hashtable_add(t, "d", 2, NULL, 0);

	CHECK(hashtable_foreach(t, count_cb, &n) == 0);
	CHECK(n == 4);

	/* a non-zero return from the callback stops the walk */
	n = 0;
	CHECK(hashtable_foreach(t, stop_cb, &n) == 42);
	CHECK(n == 3);

	/* the table cannot grow during a walk, but can after it */
	add_during_walk_table = t;
	CHECK(hashtable_foreach(t, add_cb, &rv) == 1);
	CHECK(rv == -1);
	CHECK(hashtable_add(t, "e", 2, NULL, 0) == 0);
	hashtable_free(t);
}

int
main(void)
{
	RUN(test_add_get);
	RUN(test_remove);
	RUN(test_foreach);
	DONE();
}
