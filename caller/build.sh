#!/bin/sh
set -e

rm -f wrun wcmd wstart
gcc -O2 -Wall -Wextra -std=c11 -o wrun wrun.c
if [ ! -x wcmd ] ; then ln wrun wcmd ; fi
if [ ! -x wstart ] ; then ln wrun wstart ; fi
