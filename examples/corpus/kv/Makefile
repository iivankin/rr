# kv in restricted Rust: rustc builds it and rr checks it, no Cargo;
# rr builds only what its own commands run.
# The program is one crate, src/main.rs with its modules. Its tests and
# benches sit beside the code they check; its fuzz targets are
# functions under cfg(fuzzing), named in FUZZ.

RUSTC = rustc
RR = rr
NAME = kv
# What rr sets for every crate it checks, and the program needs built.
BUILDFLAGS = --edition 2024 --crate-name $(NAME) -C panic=abort
RRFLAGS = -C opt-level=3 -C codegen-units=1
# Tests check arithmetic for overflow, as Rust's debug builds and rr
# fuz's do; the program and its benches are built without, as it ships.
TESTFLAGS = $(RRFLAGS) -C overflow-checks=on
LTOFLAGS = -C lto=fat
OUT = build
# Windows names its executables .exe.
EXE = $(if $(filter Windows_NT,$(OS)),.exe)
SRC = $(shell find src -name '*.rs')
# The fuzz targets: paths of fn(&[u8]) under cfg(fuzzing).
FUZZ = record::fuzz_record
FUZZTIME = 60

all: $(NAME)$(EXE)

$(NAME)$(EXE): $(SRC)
	$(RUSTC) src/main.rs $(BUILDFLAGS) $(RRFLAGS) $(LTOFLAGS) -C strip=symbols -o $@

# The #[test] items, each in a child; FILTER=word runs those whose name
# holds it.
test:
	$(RR) test src/main.rs --crate-name $(NAME) $(TESTFLAGS) -- $(FILTER)

# The #[bench] items, built as the program ships: time, allocations and
# bytes copied per iteration.
bench:
	$(RR) bench src/main.rs --crate-name $(NAME) $(RRFLAGS) -- $(FILTER)

# One style for every rr crate: fmt rewrites, format checks. The root
# brings the modules it declares.
fmt:
	$(RR) fmt src/main.rs

format:
	$(RR) fmt --check src/main.rs

# rr's rules and the compiler's diagnostics, on the program and on its
# tests; lint adds Clippy's.
check:
	$(RR) check src/main.rs --crate-name $(NAME)
	$(RR) test src/main.rs --check --crate-name $(NAME)

lint:
	$(RR) lint src/main.rs --crate-name $(NAME)
	$(RR) test src/main.rs --lint --crate-name $(NAME)

# Each target runs FUZZTIME seconds; what it found is kept in
# fuzz/TARGET/: corpus/, and a crash in artifacts/.
fuzz:
	@for t in $(FUZZ); do echo "$$t" && $(RR) fuz src/main.rs --target $$t \
		--crate-name $(NAME) -- -max_total_time=$(FUZZTIME) || exit 1; done

# Where the program allocates and copies: built with --prof, then run
# under rr prof. PROFRUN is what to run, PROFIN the file it reads on
# stdin, if any; PROFMAX fails above a budget of allocations, PROFCOPIED
# above one of bytes copied, PROFHEAP above one of bytes the heap holds
# at once.
PROFRUN = ./$(OUT)/prof/$(NAME)$(EXE) $(OUT)/prof.kv put key value
PROFIN =
PROFMAX =
PROFCOPIED =
PROFHEAP =
$(OUT)/prof/$(NAME)$(EXE): $(SRC)
	mkdir -p $(OUT)/prof
	$(RR) build --prof src/main.rs --crate-name $(NAME) $(RRFLAGS) $(LTOFLAGS) -o $@

prof: $(OUT)/prof/$(NAME)$(EXE)
	$(RR) prof $(if $(PROFMAX),--max $(PROFMAX)) \
		$(if $(PROFCOPIED),--max-copied $(PROFCOPIED)) \
		$(if $(PROFHEAP),--max-heap $(PROFHEAP)) \
		$(if $(PROFIN),--stdin $(PROFIN)) -- $(PROFRUN)

# How long the program takes, built as it ships: rr time runs TIMERUN,
# the workload PROFRUN runs, on PROFIN, five times; TIMEMS fails when
# the fastest run took more milliseconds.
TIMERUN = ./$(NAME)$(EXE) $(OUT)/time.kv put key value
TIMEMS =
time: $(NAME)$(EXE)
	mkdir -p $(OUT)
	$(RR) time $(if $(TIMEMS),--max-ms $(TIMEMS)) $(if $(PROFIN),--stdin $(PROFIN)) -- $(TIMERUN)

clean:
	rm -rf $(OUT) $(NAME)$(EXE)

.PHONY: all test bench fmt format check lint fuzz prof time clean
