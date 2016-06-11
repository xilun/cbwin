#!/bin/bash
set -e
cp wrun /usr/local/bin
cd /usr/local/bin
rm -f wcmd wstart
ln wrun wcmd
ln wrun wstart
