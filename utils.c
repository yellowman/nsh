/*
 * Steal some useful routines from top
 *
 * Copyright (c) 1984, 1989, William LeFebvre, Rice University
 * Copyright (c) 1989, 1990, 1992, William LeFebvre, Northwestern University
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS EMPLOYER BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "externs.h"

/*
 * string_index(string, array) - find string in array and return index
 */
int
string_index(char *string, char **array)
{
	int i = 0;

	while (*array != NULL) {
		if (strncmp(string, *array, strlen(string)) == 0)
			return (i);
		array++;
		i++;
	}
	return (-1);
}

/*
 * format_time(seconds) - format number of seconds into a suitable display
 * that will fit within 6 characters.  Note that this routine builds its
 * string in a static area.  If it needs to be called more than once without
 * overwriting previous data, then we will need to adopt a technique similar
 * to the one used for format_k.
 */

/*
 * Explanation: We want to keep the output within 6 characters.  For low
 * values we use the format mm:ss.  For values that exceed 999:59, we switch
 * to a format that displays hours and fractions:  hhh.tH.  For values that
 * exceed 999.9, we use hhhh.t and drop the "H" designator.  For values that
 * exceed 9999.9, we use "???".
 */

char *
format_time(time_t seconds)
{
	static char result[10];

	/* sanity protection */
	if (seconds < 0 || seconds > (99999l * 360l)) {
		strlcpy(result, "   ???", sizeof result);
	} else if (seconds >= (1000l * 60l)) {
		/* alternate (slow) method displaying hours and tenths */
		snprintf(result, sizeof(result), "%5.1fH",
		    (double) seconds / (double) (60l * 60l));

		/*
		 * It is possible that the snprintf took more than 6
		 * characters. If so, then the "H" appears as result[6].  If
		 * not, then there is a \0 in result[6].  Either way, it is
		 * safe to step on.
		 */
		result[6] = '\0';
	} else {
		/* standard method produces MMM:SS */
		/* we avoid printf as must as possible to make this quick */
		snprintf(result, sizeof(result), "%3d:%02d", seconds / 60,
		    seconds % 60);
	}
	return (result);
}

/*
 * format_k(amt) - format a kilobyte memory value, returning a string
 * suitable for display.  Returns a pointer to a static
 * area that changes each call.  "amt" is converted to a
 * string with a trailing "K".  If "amt" is 10000 or greater,
 * then it is formatted as megabytes (rounded) with a
 * trailing "M".
 */

/*
 * Compromise time.  We need to return a string, but we don't want the
 * caller to have to worry about freeing a dynamically allocated string.
 * Unfortunately, we can't just return a pointer to a static area as one
 * of the common uses of this function is in a large call to snprintf where
 * it might get invoked several times.  Our compromise is to maintain an
 * array of strings and cycle thru them with each invocation.  We make the
 * array large enough to handle the above mentioned case.  The constant
 * NUM_STRINGS defines the number of strings in this array:  we can tolerate
 * up to NUM_STRINGS calls before we start overwriting old information.
 * Keeping NUM_STRINGS a power of two will allow an intelligent optimizer
 * to convert the modulo operation into something quicker.  What a hack!
 */

#define NUM_STRINGS 8

char *
format_k(uint64_t amt)
{
	static char retarray[NUM_STRINGS][16];
	static int  idx = 0;
	char *ret, tag = 'K';

	ret = retarray[idx];
	idx = (idx + 1) % NUM_STRINGS;

	if (amt >= 10000) {
		amt /= 1024;
		tag = 'M';
		if (amt >= 10000) {
			amt /= 1024;
			tag = 'G';
		}
	}
	snprintf(ret, sizeof(retarray[0]), "%llu%c", amt, tag);
	return (ret);
}
