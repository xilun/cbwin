#!/bin/sh
set -e

rm -f wrun wcmd wstart
gcc -O2 -Wall -Wextra -pthread -std=c11 -o wrun wrun.c
ln wrun wcmd
ln wrun wstart
