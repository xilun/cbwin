#!/bin/sh
set -e

echo
echo 'WARNING: this script is deprecated - use "make all" directly'
echo

make clean
make -j2 all
