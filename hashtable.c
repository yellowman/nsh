/*
 * Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/queue.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <siphash.h>

#include "externs.h"

struct hashentry {
	STAILQ_ENTRY(hashentry) entry;
	void *key;
	size_t keysize;
	void *value;
	size_t valsize;
};

STAILQ_HEAD(hashbucket, hashentry);

#define HASHTABLE_MIN_BUCKETS	64

struct hashtable {
	struct hashbucket *buckets;
	size_t nbuckets;
	unsigned int nentries;
	unsigned int flags;
#define HASHTABLE_F_TRAVERSAL	0x01
#define HASHTABLE_F_NOMEM	0x02
	SIPHASH_KEY siphash_key;
};

static uint64_t
entry_hash(struct hashtable *t, void *key, size_t keysize)
{
	return SipHash24(&t->siphash_key, key, keysize);
}

struct hashtable *
hashtable_alloc(void)
{
	struct hashtable *t;
	const size_t nbuckets = HASHTABLE_MIN_BUCKETS;
	size_t i;

	t = calloc(1, sizeof(*t));
	if (t == NULL)
		return NULL;

	t->buckets = calloc(nbuckets, sizeof(t->buckets[0]));
	if (t->buckets == NULL) {
		free(t);
		return NULL;
	}

	for (i = 0; i < nbuckets; i++)
		STAILQ_INIT(&t->buckets[i]);
	t->nbuckets = nbuckets;
	arc4random_buf(&t->siphash_key, sizeof(t->siphash_key));

	return t;
}

void
hashtable_free(struct hashtable *t)
{
	size_t i;
	struct hashentry *e;

	for (i = 0; i < t->nbuckets; i++) {
		while (!STAILQ_EMPTY(&t->buckets[i])) {
			e = STAILQ_FIRST(&t->buckets[i]);
			STAILQ_REMOVE(&t->buckets[i], e, hashentry, entry);
			free(e);
		}
	}
	/* Storage for keys and values should be freed by caller. */
	free(t->buckets);
	free(t);
}

static int
table_resize(struct hashtable *t, size_t nbuckets)
{
	struct hashbucket *buckets;
	size_t i;

	buckets = calloc(nbuckets, sizeof(buckets[0]));
	if (buckets == NULL) {
		if (errno != ENOMEM)
			return -1;
		/* Proceed with our current amount of hash buckets. */
		t->flags |= HASHTABLE_F_NOMEM;
		return 0;
	}

	for (i = 0; i < nbuckets; i++)
		STAILQ_INIT(&buckets[i]);

	arc4random_buf(&t->siphash_key, sizeof(t->siphash_key));

	for (i = 0; i < t->nbuckets; i++) {
		while (!STAILQ_EMPTY(&t->buckets[i])) {
			struct hashentry *e;
			uint64_t idx;
			e = STAILQ_FIRST(&t->buckets[i]);
			STAILQ_REMOVE(&t->buckets[i], e, hashentry, entry);
			idx = entry_hash(t, e->key, e->keysize) % nbuckets;
			STAILQ_INSERT_HEAD(&buckets[idx], e, entry);
		}
	}

	free(t->buckets);
	t->buckets = buckets;
	t->nbuckets = nbuckets;
	return 0;
}

static int
table_grow(struct hashtable *t)
{
	size_t nbuckets;

	if (t->flags & HASHTABLE_F_NOMEM)
		return 0;

	if (t->nbuckets >= UINT_MAX / 2)
		nbuckets = UINT_MAX;
	else
		nbuckets = t->nbuckets * 2;

	return table_resize(t, nbuckets);
}

int
hashtable_add(struct hashtable *t, void *key, size_t keysize,
    void *value, size_t valsize)
{
	struct hashentry *e;
	uint64_t idx;
	struct hashbucket *bucket;

	/*
	 * Do not allow adding more entries during traversal.
	 * This function may resize the table.
	 */
	if (t->flags & HASHTABLE_F_TRAVERSAL)
		return -1;

	if (t->nentries == UINT_MAX)
		return -1;

	idx = entry_hash(t, key, keysize) % t->nbuckets;
	bucket = &t->buckets[idx];

	/* Require unique keys. */
	STAILQ_FOREACH(e, bucket, entry) {
		if (e->keysize == keysize && memcmp(e->key, key, keysize) == 0)
			return -1;
	}

	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return -1;

	e->key = key;
	e->keysize = keysize;
	e->value = value;
	e->valsize = valsize;

	STAILQ_INSERT_HEAD(bucket, e, entry);
	t->nentries++;

	if (t->nbuckets < t->nentries)
		if (table_grow(t) == -1)
			return -1;

	return 0;
}

static struct hashentry *
find_entry(struct hashtable *t, void *key, size_t keysize)
{
	uint64_t idx = entry_hash(t, key, keysize) % t->nbuckets;
	struct hashbucket *bucket = &t->buckets[idx];
	struct hashentry *e;

	STAILQ_FOREACH(e, bucket, entry) {
		if (e->keysize == keysize && memcmp(e->key, key, keysize) == 0)
			return e;
	}

	return NULL;
}

void *
hashtable_get_keyptr(struct hashtable *t, void *key, size_t keysize)
{
	struct hashentry *e = find_entry(t, key, keysize);
	return e ? e->key : NULL;
}

void *
hashtable_get_value(struct hashtable *t, void *key, size_t keysize)
{
	struct hashentry *e = find_entry(t, key, keysize);
	return e ? e->value : NULL;
}

int
hashtable_remove(struct hashtable *t, void **keyptr, void **value,
    size_t *valsize, void *key, size_t keysize)
{
	uint64_t idx;
	struct hashbucket *bucket;
	struct hashentry *e;

	if (keyptr)
		*keyptr = NULL;
	if (value)
		*value = NULL;
	if (valsize)
		*valsize = 0;

	if (t->nentries == 0)
		return -1;

	idx = entry_hash(t, key, keysize) % t->nbuckets;
	bucket = &t->buckets[idx];
	STAILQ_FOREACH(e, bucket, entry) {
		if (e->keysize == keysize && memcmp(e->key, key, keysize) == 0)
			break;
	}
	if (e == NULL)
		return -1;

	if (keyptr)
		*keyptr = e->key;
	if (value)
		*value = e->value;
	if (valsize)
		*valsize = e->valsize;

	STAILQ_REMOVE(bucket, e, hashentry, entry);
	free(e);
	t->nentries--;

	return 0;
}

int
hashtable_contains(struct hashtable *t, void *key, size_t keysize)
{
	struct hashentry *e = find_entry(t, key, keysize);
	return e ? 1 : 0;
}

int
hashtable_foreach(struct hashtable *t,
    int (*cb)(void *, size_t, void *, size_t, void *),
    void *cb_arg)
{
	struct hashbucket *bucket;
	struct hashentry *e, *tmp;
	size_t i;
	int ret = 0;

	t->flags |= HASHTABLE_F_TRAVERSAL;
	for (i = 0; i < t->nbuckets; i++) {
		bucket = &t->buckets[i];
		STAILQ_FOREACH_SAFE(e, bucket, entry, tmp) {
			ret = (*cb)(e->key, e->keysize, e->value, e->valsize,
			    cb_arg);
			if (ret)
				goto done;
		}
	}
done:
	t->flags &= ~HASHTABLE_F_TRAVERSAL;
	return ret;
}

int
hashtable_num_entries(struct hashtable *t)
{
	return t->nentries;
}
