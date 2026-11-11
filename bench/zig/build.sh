#!/bin/sh
# Build bench/zig/server with a pinned Zig, fetched on first use.
#
#   ./build.sh                 native build (Linux), or a cross build for x86_64 Linux elsewhere
#   TARGET=x86_64-linux-gnu ./build.sh
#   ZIG_TOOLS=/some/dir ./build.sh   where Zig is kept (default: bench/zig/.tools)
#
# The checksums are the `shasum` fields of https://ziglang.org/download/index.json for this
# release; a tarball that does not match is deleted and the build stops. When `minisign` is
# installed, the tarball's signature is checked as well against the key published on
# https://ziglang.org/download/.
set -eu

ZIG_VERSION=0.17.1
ZIG_MIRROR=https://ziglang.org/download
ZIG_PUBKEY=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U

here=$(cd "$(dirname "$0")" && pwd)
tools=${ZIG_TOOLS:-$here/.tools}

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) platform=x86_64-linux ;;
Linux-aarch64 | Linux-arm64) platform=aarch64-linux ;;
Darwin-arm64) platform=aarch64-macos ;;
Darwin-x86_64) platform=x86_64-macos ;;
*) echo "build.sh: no Zig $ZIG_VERSION for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

case $platform in
x86_64-linux) sha=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a ;;
aarch64-linux) sha=a1546d5646eb184437918d6635ca6b762a0e889eac09cef720ee7a1ed3fe7795 ;;
aarch64-macos) sha=75f1bc7a1e9852f17ec9a0c1895f767c4ec56d46bc8a834920eece1d0359dd8d ;;
x86_64-macos) sha=9af07b20319fbd0c92ee46ad23e81d6a782b1aaea2cfb8dcbff35f1d2c7ddbb7 ;;
esac

name=zig-$platform-$ZIG_VERSION
zig=$tools/$name/zig

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

fetch() { # URL FILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}

if [ ! -x "$zig" ] || [ "$("$zig" version)" != "$ZIG_VERSION" ]; then
	mkdir -p "$tools"
	tarball=$tools/$name.tar.xz
	url=$ZIG_MIRROR/$ZIG_VERSION/$name.tar.xz
	echo "build.sh: fetching $url" >&2
	fetch "$url" "$tarball.part"
	got=$(sha256 "$tarball.part")
	if [ "$got" != "$sha" ]; then
		rm -f "$tarball.part"
		echo "build.sh: sha256 mismatch for $name.tar.xz: got $got, want $sha" >&2
		exit 1
	fi
	if command -v minisign >/dev/null 2>&1; then
		fetch "$url.minisig" "$tarball.minisig"
		if ! minisign -Vq -P "$ZIG_PUBKEY" -m "$tarball.part" -x "$tarball.minisig"; then
			rm -f "$tarball.part" "$tarball.minisig"
			echo "build.sh: bad minisign signature for $name.tar.xz" >&2
			exit 1
		fi
		rm -f "$tarball.minisig"
	fi
	mv "$tarball.part" "$tarball"
	rm -rf "${tools:?}/$name"
	tar -C "$tools" -xJf "$tarball"
	rm -f "$tarball"
	[ "$("$zig" version)" = "$ZIG_VERSION" ]
fi

# Keep Zig's caches next to the build instead of in ~/.cache.
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$here/.zig-cache}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$here/.zig-cache}"

# The server is Linux-only. On Linux build for this machine's CPU; elsewhere cross-compile.
if [ -z "${TARGET:-}" ] && [ "$(uname -s)" != Linux ]; then
	TARGET=x86_64-linux-gnu
fi

cd "$here"
"$zig" build-exe -O ReleaseFast ${TARGET:+-target "$TARGET"} -femit-bin="$here/server" server.zig
echo "build.sh: built $here/server with Zig $ZIG_VERSION${TARGET:+ for $TARGET}" >&2
