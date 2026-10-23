#!/bin/sh
# Install rr from its GitHub release, for macOS arm64 and Linux x86_64 and
# aarch64:
#
#     curl -fsSL https://raw.githubusercontent.com/iivankin/rr/main/install.sh | sh
#
# By default the distribution goes to ~/.local/share/rr and a link to rr to
# ~/.local/bin. RR_INSTALL names another directory for the distribution and
# links nothing: rr is then RR_INSTALL/rr. RR_VERSION picks a release tag
# instead of the latest.
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
dest="${RR_INSTALL:-$HOME/.local/share/rr}"
bin="$HOME/.local/bin"

# Replace only a directory that holds rr, never someone's other files.
if [ -e "$dest" ] && ! { [ -f "$dest/rr" ] && [ -d "$dest/lib/rustlib" ]; }; then
    [ -d "$dest" ] && [ -z "$(ls -A "$dest")" ] ||
        die "$dest exists and is not an rr distribution"
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

# The new distribution is unpacked beside its destination, so that it
# replaces the old one by a rename on the same file system.
parent="$(dirname "$dest")"
mkdir -p "$parent"
tmp="$(mktemp -d "$parent/.rr-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $name from $url"
fetch "$url/$name.tar.gz" "$tmp/$name.tar.gz"
fetch "$url/SHA256SUMS" "$tmp/SHA256SUMS"
want="$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no $name.tar.gz"
[ "$(sha256 "$tmp/$name.tar.gz")" = "$want" ] || die "$name.tar.gz: checksum mismatch"
tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
"$tmp/$name/rr" --version >/dev/null || die "the downloaded rr does not run"

if [ -e "$dest" ]; then
    mv "$dest" "$tmp/old"
fi
mv "$tmp/$name" "$dest"
echo "Installed $("$dest/rr" --version) in $dest"

if [ -n "${RR_INSTALL:-}" ]; then
    echo "Run it as $dest/rr, or add $dest to PATH."
    exit 0
fi
# rr finds its distribution through the link.
mkdir -p "$bin"
ln -sf "$dest/rr" "$bin/rr"
echo "Linked $bin/rr"
case ":$PATH:" in
*":$bin:"*) ;;
*) echo "Add $bin to PATH: export PATH=\"$bin:\$PATH\"" ;;
esac
