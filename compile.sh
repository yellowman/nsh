#!/bin/sh
# $nsh: compile.sh,v 1.4 2003/02/18 09:29:46 chris Exp $

cat >compile.c <<END
char compiled[] = "`/bin/date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`/usr/bin/whoami`";
char compiledon[] = "`/usr/sbin/sysctl -n kern.version`";
char compilehost[] = "`uname -n`";
END
