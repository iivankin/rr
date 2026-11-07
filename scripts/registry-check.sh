#!/bin/sh
# Adds registry components to a fresh rr project and runs every check of
# the template on them: format, check, lint, test, bench. A warning other
# than dead code and unused imports (the program does not call the
# components) fails.
#
#   RR=rr RRADD=rr scripts/registry-check.sh DIR COMPONENT...
#
# RR runs the checks; RRADD runs rr add (a build with the add command).
# With TARGETS, other targets whose standard library the toolchain has
# (rustup target add), the code and its tests are also checked and linted
# for each of them: code under #[cfg(target_os)] compiles only where it is
# checked.
set -eu
RR=${RR:-rr}
RRADD=${RRADD:-$RR}
here=$(cd "$(dirname "$0")/.." && pwd)
dir=$1
shift
rm -rf "$dir"
"$RR" init "$dir" >/dev/null
cd "$dir"
for name in "$@"; do
	"$RRADD" add "$here/registry/$name/$name.json"
done
# rr add declares each component in src/base/mod.rs; the root declares base.
grep -q '^mod base;' src/main.rs || perl -pi -e 's|^(// The operating system)|mod base;\n$1|' src/main.rs
# rr fmt sorts the mod lines; the components it must leave as they came.
"$RR" fmt src/main.rs
for f in $(find src/base -name '*.rs' ! -path src/base/mod.rs); do
	r=$here/registry/${f#src/base/}
	[ -e "$r" ] && { cmp -s "$f" "$r" || { echo "registry-check: rr fmt changes $r"; diff "$r" "$f" | head -20; exit 1; }; }
done
log=$(make RR="$RR" check lint test bench 2>&1) || { printf '%s\n' "$log"; exit 1; }
printf '%s\n' "$log" | grep -E '^(test|bench|rr test|rr bench)' || true
if printf '%s\n' "$log" | grep -E '^(warning|error)' | grep -vE 'never used|never constructed|never read|unused import|warnings? emitted' ; then
	printf '%s\n' "$log"
	exit 1
fi
if [ -n "${TARGETS:-}" ]; then
	name=$(sed -n 's/^NAME = //p' Makefile)
	for t in $TARGETS; do
		for step in "check src/main.rs" "lint src/main.rs" "test src/main.rs --check" "test src/main.rs --lint"; do
			log=$("$RR" $step --crate-name "$name" --target "$t" 2>&1) || { printf '%s\n' "$log"; exit 1; }
			if printf '%s\n' "$log" | grep -E '^(warning|error)' | grep -vE 'never used|never constructed|never read|unused import|warnings? emitted' ; then
				printf '%s\n' "$log"
				exit 1
			fi
		done
		echo "registry-check: $t checked"
	done
fi
echo "registry-check: $* passed"
