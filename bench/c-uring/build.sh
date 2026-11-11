#!/bin/sh
# Build c-uring/server (Linux, gcc only): fetch liburing at a pinned
# release, run its ./configure, compile the library sources with gcc
# directly (no make) and link them statically into the server.
set -eu
cd "$(dirname "$0")"

TAG=liburing-2.15
SHA256=8d052f2622dcb3678cbaee5ff582a87572672a6c0a56533cdda5b65cb636120a
URL=https://github.com/axboe/liburing/archive/refs/tags/$TAG.tar.gz
TOP=$PWD/liburing
SRC=$TOP/liburing-$TAG          # github names the top directory so

if [ ! -f "$SRC/.built" ]; then
	rm -rf "$TOP"
	mkdir -p "$TOP"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$TOP/$TAG.tar.gz" "$URL"
	else
		wget -q -O "$TOP/$TAG.tar.gz" "$URL"
	fi
	if command -v sha256sum >/dev/null 2>&1; then
		echo "$SHA256  $TOP/$TAG.tar.gz" | sha256sum -c - >/dev/null || {
			echo "build.sh: $TAG.tar.gz checksum mismatch" >&2
			exit 1
		}
	fi
	tar -xzf "$TOP/$TAG.tar.gz" -C "$TOP"

	# configure runs make only to read the version out of liburing.spec
	# (and fails under set -e without it): stand in for that one use.
	mkdir -p "$TOP/bin"
	cat > "$TOP/bin/make" <<'SHIM'
#!/bin/sh
cat >/dev/null
for a; do last=$a; done
v=$(awk '/^Version:/ { print $2 }' "$LIBURING_SPEC")
case $last in
print-VERSION_MAJOR) echo "${v%%.*}" ;;
print-VERSION_MINOR) m=${v#*.}; echo "${m%%.*}" ;;
*) echo "make shim: unsupported $*" >&2; exit 2 ;;
esac
SHIM
	chmod +x "$TOP/bin/make"
	(cd "$SRC" && LIBURING_SPEC="$SRC/liburing.spec" PATH="$TOP/bin:$PATH" \
		./configure --cc=gcc --use-libc >"$TOP/configure.log")

	# src/Makefile: liburing_srcs and its CPPFLAGS/CFLAGS, libc build.
	for f in setup queue register syscall version; do
		gcc -O3 -march=x86-64-v2 -Wall -Wextra -Wno-unused-parameter \
			-fno-stack-protector -DLIBURING_INTERNAL \
			-D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
			-I"$SRC/src/include" -include "$SRC/config-host.h" \
			-c -o "$SRC/src/$f.o" "$SRC/src/$f.c"
	done
	touch "$SRC/.built"
fi

gcc -O2 -march=x86-64-v2 -std=gnu11 -Wall -Wextra -Werror -pthread \
	-I"$SRC/src/include" -o server server.c \
	"$SRC/src/setup.o" "$SRC/src/queue.o" "$SRC/src/register.o" \
	"$SRC/src/syscall.o" "$SRC/src/version.o"
