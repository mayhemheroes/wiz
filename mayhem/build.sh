#!/usr/bin/env bash
#
# mayhem/build.sh — build the wiz compiler + fuzz harnesses.
#
# Produces:
#   /mayhem/out/fuzz_wiz         libFuzzer harness over the full compiler pipeline (wiz::run)  -> Mayhemfile_wiz
#   /mayhem/out/fuzz_sub         libFuzzer harness over wiz::StringView                        -> Mayhemfile_sub
#   /mayhem/out/fuzz_{wiz,sub}-standalone  run-once (non-fuzzer) reproducers
#   /mayhem/bin/wiz              NORMAL-flags wiz build for the functional test suite (test.sh)
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Full halting ASan+UBSan, except UBSan is scoped out of int128.h via the ignorelist: its
# intentional two's-complement bit-twiddling (Int128(INT_MIN) negation) trips UBSan
# deterministically during compiler startup on every input, aborting exec #1 otherwise.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize-ignorelist=$SRC/mayhem/ubsan-ignorelist.txt"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
mkdir -p "$SRC/out"

BASE_CXXFLAGS="-D_POSIX_SOURCE -O1 -std=c++17 -MMD -Wall -Wextra -Wnon-virtual-dtor -fno-exceptions -fno-rtti"

# 1) Build the whole project sanitized+instrumented (fuzzer coverage baked into every object so
#    the in-process harness explores the real compiler). Upstream Makefile with flag overrides:
#    sanitizers + DWARF-3, no -flto/-s (keep symbols).
make clean >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS" CXX="$CXX" WERR=0 \
    CXX_FLAGS="$BASE_CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
    LXXFLAGS="-lm $SANITIZER_FLAGS $DEBUG_FLAGS"

# 2a) The `wiz` harness: fuzzes the full CLI pipeline in-process via wiz::run(). Reuses the
#     sanitized project objects; wiz.cpp is recompiled with main() renamed out of the way so
#     the fuzzing engine supplies its own entry point.
PROJECT_OBJS=$(find src -name '*.o' ! -name 'wiz.o')
$CXX $BASE_CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -Dmain=wiz_cli_main \
    -c src/wiz/wiz.cpp -Isrc -o /tmp/wiz_nomain.o
$CXX $BASE_CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_wiz.cpp" /tmp/wiz_nomain.o $PROJECT_OBJS -Isrc -lm \
    -o "$SRC/out/fuzz_wiz"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $BASE_CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
    "$SRC/mayhem/fuzz_wiz.cpp" /tmp/standalone_main.o /tmp/wiz_nomain.o $PROJECT_OBJS -Isrc -lm \
    -o "$SRC/out/fuzz_wiz-standalone"

# 2b) The StringView harness: fuzzer binary + standalone run-once reproducer.
#    StringView is header-only; the harness TU carries the instrumentation.
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_sub.cpp" -I"$SRC/src/wiz/utility" -I"$SRC/src" \
    -o "$SRC/out/fuzz_sub"
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_sub.cpp" /tmp/standalone_main.o -I"$SRC/src/wiz/utility" -I"$SRC/src" \
    -o "$SRC/out/fuzz_sub-standalone"

# 3) Test-suite build: wiz with the project's NORMAL flags (independent, clean build) at bin/wiz.
#    mayhem/test.sh only RUNS tests/wiztests.py against this binary — it never compiles.
make clean >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS" CXX="$CXX" WERR=0 \
    CXX_FLAGS="$BASE_CXXFLAGS $COVERAGE_FLAGS" \
    LXXFLAGS="-lm $COVERAGE_FLAGS"

echo "build.sh: done"
ls -l "$SRC/out" "$SRC/bin"
