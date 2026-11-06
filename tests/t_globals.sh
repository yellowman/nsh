#!/bin/sh
#
# Check that the globals globals.list calls a session's are the ones the
# SGLOBAL tables hold, and each in the table of its own file: a session
# global missing from a table would leak from one session to the next.
# session.c's own table holds main.c's, makeargv.c's, prompt.c's and
# bgpcommands.c's.
#
# Usage: t_globals.sh [top]	(default ..)

top=${1:-..}
tmp=${TMPDIR:-/tmp}/t_globals.$$
trap 'rm -f "$tmp".*' 0 1 2 15

# file name, for each session global globals.list names
tr -d '\r' < "$top/globals.list" | awk '
	/^#/ || /^[ \t]*$/ { next }
	/^[^ \t]/ { file = $1; class = $2; first = 3 }
	/^[ \t]/ { first = 1 }
	class == "session" {
		for (i = first; i <= NF; i++)
			print file, $i
	}' | sort > "$tmp.listed"

# file name, for each SGLOBAL(name); session.c's for the files it holds
for f in "$top"/*.c; do
	tr -d '\r' < "$f" | grep -o 'SGLOBAL([A-Za-z_][A-Za-z0-9_]*)' |
	    sed 's/SGLOBAL(\(.*\))/\1/' | while read -r name; do
		echo "$(basename "$f") $name"
	done
done | sort > "$tmp.tabled"

# session.c's table holds other files' globals: compare names alone there
held="main.c makeargv.c prompt.c bgpcommands.c"
for f in $held; do
	awk -v f="$f" '$1 == f { print "session.c", $2 }' "$tmp.listed"
done > "$tmp.held"
awk -v held="$held" 'BEGIN { n = split(held, h, " "); for (i = 1; i <= n;
	i++) skip[h[i]] = 1 } !skip[$1]' "$tmp.listed" > "$tmp.own"
sort "$tmp.own" "$tmp.held" > "$tmp.want"

fail=0
n=$(wc -l < "$tmp.want" | tr -d ' ')
if [ "$n" -eq 0 ]; then
	echo "FAIL no session globals found in $top/globals.list"
	fail=1
fi
comm -23 "$tmp.want" "$tmp.tabled" | while read -r file name; do
	echo "FAIL $name: a session global (globals.list) in no SGLOBAL table of $file"
done
comm -13 "$tmp.want" "$tmp.tabled" | while read -r file name; do
	echo "FAIL $name: in $file's SGLOBAL table, not a session global of it in globals.list"
done
if [ -n "$(comm -3 "$tmp.want" "$tmp.tabled")" ]; then
	fail=1
fi

if [ $fail -eq 0 ]; then
	echo "$n passed, 0 failed, 0 known bugs"
	exit 0
fi
echo "FAILED"
exit 1
