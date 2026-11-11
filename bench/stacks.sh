# The stacks, and how each server is run (sourced by check.sh and run.sh):
# one loop on one core where the runtime has a choice.
STACKS="rr c-uring c-epoll zig monoio tokio go node"
TOOLS=${TOOLS:-$here/../tools}
NODE=${NODE:-$(ls -d "$TOOLS"/node-*/bin/node 2>/dev/null | tail -1)}
command_of() {
	case $1 in
	rr) echo "$here/rr/build/server" ;;
	go) echo "env GOMAXPROCS=1 $here/go/server" ;;
	go-nethttp) echo "env GOMAXPROCS=1 $here/go/server nethttp-" ;;
	node) echo "$NODE $here/node/server.js" ;;
	*) echo "$here/$1/server" ;;
	esac
}
