#!/bin/sh
# Adds registry components to a fresh rr project and runs every check of
# the template on them: format, check, lint, test, bench. A warning other
# than dead code and unused imports (the program does not call the
# components) fails.
#
#   RR=rr RRADD=rr OPTIONS='os=linux arch=aarch64' scripts/registry-check.sh DIR COMPONENT...
#
# RR runs the checks; RRADD runs rr add (a build with the add command).
# OPTIONS are rr add's answers, each NAME=A[,B]: what they cut must leave
# code that checks as the whole does.
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
answers=
for o in ${OPTIONS:-}; do
	answers="$answers --option $o"
done
paths=
for name in "$@"; do
	paths="$paths $here/registry/$name.rs"
	# A component is as rr fmt leaves it: rustfmt moves a mark that
	# follows a closing brace onto that line, where rr add would not see it.
	cp "$here/registry/$name.rs" .source.rs
	"$RR" fmt .source.rs
	cmp -s "$here/registry/$name.rs" .source.rs || { echo "registry-check: rr fmt changes registry/$name.rs"; diff "$here/registry/$name.rs" .source.rs | head -20; exit 1; }
	rm -f .source.rs
done
"$RRADD" add --yes $answers $paths
# rr add declares each component in src/base/mod.rs; the root declares base.
grep -q '^mod base;' src/main.rs || perl -pi -e 's|^(// The operating system)|mod base;\n$1|' src/main.rs
# rr fmt sorts the mod lines; the components, as rr add cut them, it
# must leave as they came.
rm -rf .added && cp -R src/base .added
"$RR" fmt src/main.rs
for f in $(find src/base -name '*.rs' ! -path src/base/mod.rs); do
	a=.added/${f#src/base/}
	cmp -s "$f" "$a" || { echo "registry-check: rr fmt changes $f as rr add wrote it"; diff "$a" "$f" | head -20; exit 1; }
done
rm -rf .added
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
