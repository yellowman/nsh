#!/bin/sh
# Run each test given, a program or a .sh script, and report which
# failed. Exit status is non-zero if any test failed or crashed.

failed=""
for t in "$@"; do
	echo "==> $t"
	case "$t" in
	*.sh)	sh ./"$t" .. ;;
	*)	./"$t" ;;
	esac
	if [ $? -ne 0 ]; then
		failed="$failed $t"
	fi
done

echo
if [ -n "$failed" ]; then
	echo "FAILED:$failed"
	exit 1
fi
echo "all tests passed"
