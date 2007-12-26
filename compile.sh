#!/bin/sh
# $nsh: compile.sh,v 1.7 2007/12/26 06:10:47 chris Exp $

cat >compile.c <<__END
char compiled[] = "`/bin/date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`/usr/bin/whoami`";
char compilehost[] = "`uname -n`";
__END
