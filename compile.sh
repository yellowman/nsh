#!/bin/sh

cat >compile.c <<END
char compiled[] = "`/bin/date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`/usr/bin/whoami`";
char compiledon[] = "`/usr/sbin/sysctl -n kern.version`";
END
