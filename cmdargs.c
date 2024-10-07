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
#include <sys/socket.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include "externs.h"
#include "commands.h"

/*
 * cmd, multiple args
 *
 * If no error occurs then return the program's exit code (>= 0).
 * Return -1 on error to run the program or if the program was
 * terminated in an abnormal way, such as being killed by a signal.
 */
int
cmdargs(char *cmd, char *arg[])
{
	return cmdargs_output(cmd, arg, -1, -1);
}

/*
 * cmd, multiple args, capture stdout and stderr output
 *
 * If no error occurs then return the program's exit code (>= 0).
 * Return -1 on error to run the program or if the program was
 * terminated in an abnormal way, such as being killed by a signal.
 */
int
cmdargs_output(char *cmd, char *arg[], int stdoutfd, int stderrfd)
{
	return cmdargs_output_setenv(cmd, arg, stdoutfd, stderrfd, NULL, 0);
}

int
cmdargs_nowait(char *cmd, char *arg[], int pipefd)
{
	return cmdargs_output_setenv(cmd, arg, -1, -1, NULL, pipefd);
}

int
cmdargs_output_setenv(char *cmd, char *arg[], int stdoutfd, int stderrfd,
    char **env, int pipefd)
{
	sig_t sigint, sigquit, sigchld;
	int status = -1;

	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);

	switch (child = fork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			return -1;

		case 0:
		{
			char *shellp = cmd;

			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);

			if (nsh_setrtable(cli_rtable))
				_exit(0);

			if (stdoutfd != -1) {
				if (stdoutfd != STDOUT_FILENO &&
				    dup2(stdoutfd, STDOUT_FILENO) == -1) {
					printf("%% dup2: %s\n",
					    strerror(errno));
					_exit(0);
				}
			}
			if (stderrfd != -1) {
				if (stderrfd != STDERR_FILENO &&
				    dup2(stderrfd, STDERR_FILENO) == -1) {
					printf("%% dup2 failed: %s\n",
					    strerror(errno));
					_exit(0);
				}
			}

			if (env)
				execvpe(shellp, arg, env);
			else
				execv(shellp, arg);
			printf("%% exec '%s' failed: %s\n", shellp,
			    strerror(errno));
			_exit(127); /* same as what ksh(1) would do here */
		}
			break;
		default:
			if (pipefd)
				return 0;
			signal(SIGALRM, sigalarm);
			wait(&status);  /* Wait for cmd to complete */
			if (WIFEXITED(status)) /* normal exit? */
				status = WEXITSTATUS(status); /* exit code */
			break;
	}

	signal(SIGINT, sigint);
	signal(SIGQUIT, sigquit);
	signal(SIGCHLD, sigchld);
	signal(SIGALRM, SIG_DFL);
	child = -1;

	return status;
}

int
cmdargs_wait_for_child(void)
{
	sig_t sigint, sigquit, sigchld;
	int status = 127;

	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);

	if (child != -1) {
		signal(SIGALRM, sigalarm);
		wait(&status);  /* Wait for cmd to complete */
		if (WIFEXITED(status)) /* normal exit? */
			status = WEXITSTATUS(status); /* exit code */
		signal(SIGINT, sigint);
		signal(SIGQUIT, sigquit);
		signal(SIGCHLD, sigchld);
		signal(SIGALRM, SIG_DFL);
		child = -1;
	}

	return status;
}

int
nsh_setrtable(int rtableid)
{
	int ret = 0;

	if (getrtable() == rtableid)
		return 0;

	if (setrtable(rtableid) < 0) {
		ret = errno;
		switch(errno) {
		case EINVAL:
			printf("%% rtable %d not initialised\n", rtableid);
			printf("%% set rdomain %d and an IP address on an interface to initalise the rtable\n", rtableid);
			break;
		case EPERM:
			printf("%% Privileged required\n");
			break;
		default:
			printf("%% setrtable failed: %d\n", errno);
		}
	} else
		init_bgpd_socket_path(rtableid);

	return(ret);
}
