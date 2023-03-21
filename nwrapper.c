/*
 * This program acts as a login shell for users who are meant to login
 * to nsh and nothing else.
 */

/*
 * E.g. to allow the user 'stacy' to login to this shell and launch 
 * nsh interactive mode only put the following line in /etc/doas.conf:
 * 
 * permit nopass stacy as root cmd /usr/local/bin/nsh args
 *
 * to allow a restricted user e.g. a backup user 'backupuser' 
 * run nsh in non interactive mode and run a specific nshrc script
 * put the following line in /etc/doas.conf 
 * permit nopass backupuser as root cmd /usr/local/bin/nsh args -c /home/backupuser/showrun.nshrc  
 */

#include <stdio.h>
#include <unistd.h>

int
main()
{
 execl("/usr/bin/doas","/usr/bin/doas","/usr/local/bin/nsh", (char *)NULL);
 return 0;
 
}
