#!/bin/sh
# Build c-epoll/server (Linux, gcc only).
set -eu
cd "$(dirname "$0")"
gcc -O2 -march=x86-64-v2 -std=gnu11 -Wall -Wextra -Werror -pthread -o server server.c
