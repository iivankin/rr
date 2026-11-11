#!/bin/sh
# Check c-uring/server (run build.sh here and in ../c-epoll first):
# the proxy backend is c-epoll json, as in the benchmark.
cd "$(dirname "$0")" && exec bash ../c-common/test.sh ./server ../c-epoll/server
