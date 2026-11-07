#!/bin/sh
# Install rr from its GitHub release, for macOS arm64 and Linux x86_64 and
# aarch64:
#
#     curl -fsSL https://raw.githubusercontent.com/iivankin/rr/main/install.sh | sh
#
# rr is a Clippy-like tool on the official Rust release it is built on:
# rustup installs that toolchain, rr goes into its bin/ beside rustc, as
# clippy-driver does, with what is its own in lib/rustlib/rr/, and a link
# to it into ~/.local/bin. RR_VERSION picks a release tag instead of the
# latest.
set -eu

repo=iivankin/rr

die() {
    echo "rr install: $*" >&2
    exit 1
}

case "$(uname -s)-$(uname -m)" in
Darwin-arm64) name=rr-macos-arm64 ;;
Linux-x86_64 | Linux-amd64) name=rr-linux-x86_64 ;;
Linux-aarch64 | Linux-arm64) name=rr-linux-aarch64 ;;
*) die "no rr for $(uname -s) $(uname -m); on Windows use install.ps1" ;;
esac

if [ -n "${RR_VERSION:-}" ]; then
    url="https://github.com/$repo/releases/download/$RR_VERSION"
else
    url="https://github.com/$repo/releases/latest/download"
fi
bin="$HOME/.local/bin"

# rustup, also where its installer leaves it when PATH does not have it yet.
if command -v rustup >/dev/null; then
    rustup=rustup
elif [ -x "${CARGO_HOME:-$HOME/.cargo}/bin/rustup" ]; then
    rustup="${CARGO_HOME:-$HOME/.cargo}/bin/rustup"
else
    die "needs rustup, which installs Rust: https://rustup.rs"
fi
if command -v curl >/dev/null; then
    fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null; then
    fetch() { wget -q -O "$2" "$1"; }
else
    die "needs curl or wget"
fi
if command -v sha256sum >/dev/null; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "needs sha256sum or shasum"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $name from $url"
fetch "$url/$name.tar.gz" "$tmp/$name.tar.gz"
fetch "$url/SHA256SUMS" "$tmp/SHA256SUMS"
want="$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no $name.tar.gz"
[ "$(sha256 "$tmp/$name.tar.gz")" = "$want" ] || die "$name.tar.gz: checksum mismatch"
mkdir "$tmp/rr"
tar -xzf "$tmp/$name.tar.gz" -C "$tmp/rr"
release="$(cat "$tmp/rr/lib/rustlib/rr/rust-version")"
[ -n "$release" ] || die "the archive names no Rust release"

echo "Installing Rust $release with rustup"
"$rustup" toolchain install "$release" --profile minimal --no-self-update
toolchain="$("$rustup" run "$release" rustc --print sysroot)"
[ -d "$toolchain/bin" ] || die "no toolchain at $toolchain"
# rr's own files are replaced whole; the toolchain's are not touched. The
# old rr is removed, not written over: macOS keeps a signed executable's
# signature by its file, and kills a process from one rewritten in place.
rm -rf "$toolchain/lib/rustlib/rr" "$toolchain/bin/rr"
cp -R "$tmp/rr/." "$toolchain/"
"$toolchain/bin/rr" --version >/dev/null || die "the installed rr does not run"
echo "Installed $("$toolchain/bin/rr" --version) in $toolchain"

mkdir -p "$bin"
ln -sf "$toolchain/bin/rr" "$bin/rr"
echo "Linked $bin/rr"
case ":$PATH:" in
*":$bin:"*) ;;
*) echo "Add $bin to PATH: export PATH=\"$bin:\$PATH\"" ;;
esac
