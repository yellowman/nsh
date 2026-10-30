/*
 * Copyright (c) 2002-2008 Chris Cappuccio <chris@nmedia.net>
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

/* nsh's own commands, in nshcmds.c */

int clear(int, char **, ...);
int doverbose(int, char **, ...);
int doediting(int, char **, ...);
int show_hostname(int, char **, ...);
int showcmd(int, char **, ...);
int flush_history(int, char **, ...);
int op_ask(char *, int, char **, int);
int int_logger(int, char **, ...);
int int_ping(int, char **, ...);
int int_ping6(int, char **, ...);
int int_traceroute(int, char **, ...);
int int_traceroute6(int, char **, ...);
int int_ssh(int, char **, ...);
int int_telnet(int, char **, ...);
int int_do(int, char **, ...);
int int_setenv(int, char **, ...);
int int_unsetenv(int, char **, ...);
int int_saveenv(int, char **, ...);
int int_show(int, char **, ...);
int int_who(int, char **, ...);
int int_doverbose(int, char **, ...);
int int_doediting(int, char **, ...);
int int_manual(int, char **, ...);
int int_shell(int, char **, ...);
int int_clear(int, char **, ...);
int int_help(int, char **, ...);
int logger(int, char **, ...);
int manual(int, char **, ...);
int nocmd(int, char **, ...);
int docmd(int, char **, ...);
int setenvcmd(int, char **, ...);
int unsetenvcmd(int, char **, ...);
int saveenvcmd(int, char **, ...);
int shell(int, char **, ...);
int ping(int, char **, ...);
int ping6(int, char **, ...);
int traceroute(int, char **, ...);
int traceroute6(int, char **, ...);
int ssh(int, char **, ...);
int telnet(int, char **, ...);
int nreboot(int, char **, ...);
int halt(int, char **, ...);
int powerdown(int, char **, ...);

/* and their help */
extern char rtablehelp[], clearhelp[], showhelp[], flushhelp[];
extern char pinghelp[], ping6help[], tracerthelp[], tracert6help[];
extern char sshhelp[], telnethelp[], quithelp[], exithelp[];
extern char verbosehelp[], editinghelp[], confighelp[], rollbackhelp[];
extern char loggerhelp[], whohelp[], dohelp[], setenvhelp[];
extern char unsetenvhelp[], saveenvhelp[], shellhelp[], commithelp[];
extern char nreboothelp[], halthelp[], powerdownhelp[], helphelp[];
extern char manhelp[];
