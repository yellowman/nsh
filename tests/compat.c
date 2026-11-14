/*
 * Stand-ins for the BSD functions the portable tests need, for building
 * them on a system without them (MinGW). Not used on OpenBSD.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

void *
reallocarray(void *p, size_t n, size_t size)
{
	if (size != 0 && n > SIZE_MAX / size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(p, n * size);
}

char *
strndup(const char *s, size_t n)
{
	size_t len = strnlen(s, n);
	char *d = malloc(len + 1);

	if (d == NULL)
		return NULL;
	memcpy(d, s, len);
	d[len] = '\0';
	return d;
}

ssize_t
getline(char **linep, size_t *sizep, FILE *f)
{
	size_t len = 0;
	int c;
	char *p;

	if (*linep == NULL || *sizep == 0) {
		*sizep = 128;
		if ((*linep = malloc(*sizep)) == NULL)
			return -1;
	}
	while ((c = getc(f)) != EOF) {
		if (len + 2 > *sizep) {
			if ((p = realloc(*linep, *sizep * 2)) == NULL)
				return -1;
			*linep = p;
			*sizep *= 2;
		}
		(*linep)[len++] = c;
		if (c == '\n')
			break;
	}
	if (len == 0)
		return -1;
	(*linep)[len] = '\0';
	return len;
}
