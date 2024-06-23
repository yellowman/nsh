#!/bin/sh

cat >compile.c <<__END
char compiled[] = "`/bin/date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`/usr/bin/whoami`";
char compilehost[] = "`uname -n`";
__END
