#!/bin/sh
set -e

rm -f wrun wcmd wstart
gcc -O2 -Wall -Wextra -pthread -std=c11 -o wrun -flto wrun.c xalloc.c err.c str.c
gcc -O2 -Wall -Wextra          -std=c11 -o wcmd -flto wcmd.c xalloc.c err.c
strip wrun
strip wcmd
ln wcmd wstart
