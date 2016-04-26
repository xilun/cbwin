#!/bin/sh
set -e

gcc -O2 -Wall -Wextra -std=c11 -o wcmd wcmd.c
