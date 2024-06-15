/*
 * Copyright (c) 2008-2009 Chris Cappuccio <chris@nmedia.net>
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

#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include <net/if.h>	/* IFNAMSIZ */

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"
#include "commands.h"

char prompt[128];
char saved_prompt[sizeof(prompt)];

char *
cprompt(void)
{
	int pr;
	char tmp[4];

	if (cli_rtable)
		snprintf(tmp, sizeof(tmp), "%d", cli_rtable);

	gethostname(hbuf, sizeof(hbuf));
	pr = priv | cli_rtable | config_mode;
	snprintf(prompt, sizeof(prompt), "%s%s%s%s%s%s%s%s%s/", hbuf,
	    pr ? "(" : "",
	    config_mode ? "config" : "",
	    config_mode && priv ? "-" : "",
	    priv ? "p" : "",
	    (( priv && cli_rtable) || (config_mode && cli_rtable)) ? "-" : "",
	    cli_rtable ? "rtable " : "", cli_rtable ? tmp : "",
	    pr ?")" : "");

	return(prompt);
}

char *
iprompt(void)
{
	gethostname(hbuf, sizeof(hbuf));
	snprintf(prompt, sizeof(prompt), "%s(%s-%s)/", hbuf,
	    bridge ? "bridge" : "interface", ifname);

	return(prompt);
}

char *
pprompt(void)
{
	return(prompt);
}

void
setprompt(const char *s)
{
	strlcpy(saved_prompt, prompt, sizeof(saved_prompt));
	strlcpy(prompt, s, sizeof(prompt));
}

void
restoreprompt(void)
{
	strlcpy(prompt, saved_prompt, sizeof(prompt));
}
