/*
 * Copyright (c) 2015 Ingo Schwarze <schwarze@openbsd.org>
 * Copyright (c) 2018, 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <langinfo.h>

#include "externs.h"

/* Create newly allocated wide-character string equivalent to a byte string. */
int
mbs2ws(wchar_t **ws, size_t *wlen, const char *s)
{
	char *vis = NULL;
	int err = 0;

	*ws = NULL;
	*wlen = mbstowcs(NULL, s, 0);
	if (*wlen == (size_t)-1) {
		int vislen;
		if (errno != EILSEQ)
			return -1;

		/* byte string invalid in current encoding; try to "fix" it */
		err = mbsavis(&vis, &vislen, s);
		if (err)
			return err;
		*wlen = mbstowcs(NULL, vis, 0);
		if (*wlen == (size_t)-1) {
			free(vis);
			return -1; /* give up */
		}
	}

	*ws = calloc(*wlen + 1, sizeof(**ws));
	if (*ws == NULL)
		return -1;

	if (mbstowcs(*ws, vis ? vis : s, *wlen) != *wlen)
		err = -1;

	free(vis);
	if (err) {
		free(*ws);
		*ws = NULL;
		*wlen = 0;
	}
	return err;
}

int
mbsavis(char** outp, int *widthp, const char *mbs)
{
	const char *src;  /* Iterate mbs. */
	char	 *dst;  /* Iterate *outp. */
	wchar_t	  wc;
	int	  total_width;  /* Display width of the whole string. */
	int	  width;  /* Display width of a single Unicode char. */
	int	  len;  /* Length in bytes of UTF-8 encoded string. */

	len = strlen(mbs);
	if ((*outp = malloc(len + 1)) == NULL)
		return -1;

	if (MB_CUR_MAX == 1) {
		memcpy(*outp, mbs, len + 1);
		*widthp = len;
		return 0;
	}

	src = mbs;
	dst = *outp;
	total_width = 0;
	while (*src != '\0') {
		if ((len = mbtowc(&wc, src, MB_CUR_MAX)) == -1) {
			total_width++;
			*dst++ = '?';
			src++;
		} else if ((width = wcwidth(wc)) == -1) {
			total_width++;
			*dst++ = '?';
			src += len;
		} else {
			total_width += width;
			while (len-- > 0)
				*dst++ = *src++;
		}
	}
	*dst = '\0';
	*widthp = total_width;
	return 0;
}
