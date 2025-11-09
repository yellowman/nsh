/*
 * nopt: a simple table based argument parser using genget
 *
 * Copyright (c) 2013 Chris Cappuccio <chris@nmedia.net>
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

#include <stdio.h>
#include <stdlib.h>
#include "externs.h"

int noptind;
char *nopterr;

int
nopt(int argc, char **argv, struct nopts *tokens)
{
	struct nopts *op;

	if (argc < 1)
		return -1;
	op = (struct nopts *)genget(argv[noptind], (char **)tokens,
	    sizeof(struct nopts));
	if (op == 0) {
		nopterr = "Invalid argument";
		return -1;
	}
	if (Ambiguous(op)) {
		nopterr = "Ambiguous argument";
		return -1;
	}
	if (op->type == req_2arg) {
		if ((argc - noptind) < 3) {
			nopterr = "Missing required argument";
			return -1;
		}
		noptind += 3;
	}
	if (op->type == req_arg) {
		if ((argc - noptind) < 2) {
			nopterr = "Missing required argument";
			return -1;
		}
		noptind += 2;
	}
	if (op->type == no_arg)
		noptind += 1;

	return (op->arg);
}
