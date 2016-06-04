#!/bin/sh
set -e

rm -f wrun wcmd wstart
gcc -g -O2 -Wall -Wextra -std=c11 -o wrun wrun.c fd_info.c
ln wrun wcmd
ln wrun wstart
