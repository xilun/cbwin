#!/bin/sh
set -e

rm -f wrun wcmd wstart
DEFINES="-D_XOPEN_SOURCE=700 -D_BSD_SOURCE"
gcc $DEFINES -O2 -Wall -Wextra -pthread -std=c11 -o wrun -flto wrun.c xalloc.c err.c str.c
gcc $DEFINES -O2 -Wall -Wextra          -std=c11 -o wcmd -flto wcmd.c xalloc.c err.c
strip wrun
strip wcmd
ln wcmd wstart
