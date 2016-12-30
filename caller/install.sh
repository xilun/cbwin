#!/bin/bash
set -e
rm -f /usr/local/bin/{wrun,wcmd,wstart}
install -t /usr/local/bin wrun
install -t /usr/local/bin wcmd
cd /usr/local/bin
ln wcmd wstart
