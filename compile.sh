#!/bin/sh

cat >compile.c <<END
char compiled[] = "`date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`whoami`";
END
