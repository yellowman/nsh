/* $nsh: passwd.c,v 1.3 2004/03/19 08:07:19 chris Exp $ */
/*
 * Copyright (c) 2004
 *      Christian Gut.  All rights reserved.
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
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "externs.h"

int		read_pass(char *, size_t);
int		write_pass(char *, size_t);
int		gen_salt(char*, size_t);

char *bcrypt_gensalt(u_int8_t);

/* read_pass reads the (blowfish crypted) password from a file */
int
read_pass(char *pass, size_t size)
{
	FILE           *pwdhandle;

	pwdhandle = fopen(NSHPASSWD_TEMP, "r");
	if (pwdhandle == NULL)
		return (0);
	fgets(pass, size, pwdhandle);
	fclose(pwdhandle);

	return (1);
}

/* write the crypted password to the passwd-temp file */
int
write_pass(char *cpass, size_t size)
{
	FILE           *pwdhandle;

	umask(S_IWGRP|S_IRWXO);
	pwdhandle = fopen(NSHPASSWD_TEMP, "w");
	if (pwdhandle == NULL) {
		printf("%% Unable to write run-time crypt repository: %s\n",
		    strerror(errno));
		return(0);
	}

	fprintf(pwdhandle, "%s", cpass);
	fclose(pwdhandle);

	return(1);
}

int
gen_salt(char *salt, size_t saltlen) {
	/* 6 is a rounds value like from localcipher option of login.conf */
	strlcpy(salt, bcrypt_gensalt(6), saltlen);
	return 1;
}
