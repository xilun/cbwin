#!/bin/bash
set -e
rm -f /usr/local/bin/{wrun,wcmd,wstart}
cp wrun /usr/local/bin
cp wcmd /usr/local/bin
cd /usr/local/bin
ln wcmd wstart
