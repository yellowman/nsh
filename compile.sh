#!/bin/sh
# $nsh: compile.sh,v 1.6 2005/02/10 05:54:13 chris Exp $

cat >compile.c <<E1
char compiled[] = "`/bin/date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`/usr/bin/whoami`";
E1

echo -n "char compiledon[] = " >> compile.c

IFS="" 
/usr/sbin/sysctl -n kern.version | while read line && [ -n "$line" ]; do
  echo >> compile.c
  echo -n "\"$line\\\n\"" >> compile.c
done

cat >> compile.c <<E2
;
char compilehost[] = "`uname -n`";
E2
