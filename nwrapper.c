/* $nsh: nwrapper.c,v 1.1 2003/03/27 23:33:01 chris Exp $ */

/*
 * This program acts as a login shell for users who are meant to login
 * to nsh and nothing else.
 */

/*
 * for 'stacy' to login to this shell and launch nsh, this
 * is what you would put in /etc/sudoers:
 *
 * Defaults:stacy	!authenticate
 * stacy		ALL=/bin/nsh
 */

#include <stdio.h>

main()
{
 execl("/usr/bin/sudo","/usr/bin/sudo","/bin/nsh", (char *)NULL);
}
