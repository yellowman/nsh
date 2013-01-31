/*
 * This program acts as a login shell for users who are meant to login
 * to nsh and nothing else.
 */

/*
 * for 'stacy' to login to this shell and launch nsh, this
 * is what you would put in /etc/sudoers:
 *
 * stacy		ALL=NOPASSWD:/bin/nsh
 */

#include <stdio.h>
#include <unistd.h>

main()
{
 execl("/usr/bin/sudo","/usr/bin/sudo","/bin/nsh", (char *)NULL);
}
