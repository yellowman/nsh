#!/bin/sh
echo '#include <sys/types.h>'
echo '#include <stdio.h>'
if [ "$(basename $(pwd))" = "obj" ]; then
	echo '#include "../externs.h"'
else
	echo '#include "externs.h"'
fi
echo 'struct ghs mantab[] = {'
grep '^\.Tg' "$1" | sort  | uniq | cut -d ' ' -f2 | sed -e \
	's/\(.*\)/	{ "\1", "Search for tag \1", CMPL0 NULL, 0 },/'
echo '	{ "<cr>", "Read entire manual", CMPL0 NULL, 0 },'
echo '	{ NULL, NULL, NULL, NULL, 0 }'
echo '};'
