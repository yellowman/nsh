#!/bin/sh
# $nsh: compile.sh,v 1.5 2005/02/10 05:41:35 chris Exp $

cat >compile.c <<E1
char compiled[] = "`/bin/date +"%d-%b-%y %H:%M"`";
char compiledby[] = "`/usr/bin/whoami`";
E1

echo -n "char compiledon[] = " >> compile.c

/usr/sbin/sysctl -n kern.version | while read line && [ -n "$line" ]; do
  echo >> compile.c
  echo -n "\" $line\"" >> compile.c
done

cat >> compile.c <<E2
;
char compilehost[] = "`uname -n`";
E2
