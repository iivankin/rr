#!/bin/sh
# Check c-epoll/server (run build.sh first); it is its own proxy backend.
cd "$(dirname "$0")" && exec bash ../c-common/test.sh ./server ./server
