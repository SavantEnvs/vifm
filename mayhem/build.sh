#!/usr/bin/env bash
#
# mayhem/build.sh — builds (1) vifm's own unit-test suites with the project's NORMAL flags and
# (2) the sanitized libFuzzer harnesses (+ run-once standalone reproducers) over vifm's engine.
# Runs in /mayhem as `mayhem`; re-runnable and network-free (all deps are apt -dev packages).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# The image COPY gives the tracked autotools outputs arbitrary mtimes, which makes make try to
# regenerate them (aclocal/automake are not what upstream builds with). Order them explicitly.
touch aclocal.m4; sleep 1
touch configure; sleep 1
touch Makefile.in src/Makefile.in build-aux/config.h.in

# 1) Unit-test suites, normal flags (tests link vifm's own objects, so build them first).
env -u CFLAGS -u LDFLAGS -u CPPFLAGS ./configure CC="$CC" \
    CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" >/dev/null
make -C src clean >/dev/null
env -u CFLAGS -u LDFLAGS make -C tests -j"$MAYHEM_JOBS" build

# 2) vifm itself, sanitized, with DWARF 3 (project code is what the harnesses fuzz).
env -u CFLAGS -u LDFLAGS -u CPPFLAGS ./configure CC="$CC" \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1" >/dev/null
make -C src clean >/dev/null
make -C src -j"$MAYHEM_JOBS" vifm

mapfile -t OBJS < <(find src -name '*.o' ! -path src/vifm.o | sort)
LIBS="-lpthread -lm -lrt -ldl -lncursesw"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -include build-aux/config.h -c mayhem/vifm_stubs.c -o /tmp/vifm_stubs.o

for kind in options variables keys commands matchers; do
  upper=$(echo "$kind" | tr a-z A-Z)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -Wno-unused-function -include build-aux/config.h \
      -DFUZZ_"$upper" -c mayhem/fuzz_vifm.c -o "/tmp/fuzz_$kind.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "/tmp/fuzz_$kind.o" "${OBJS[@]}" \
      /tmp/lsan_off.o /tmp/vifm_stubs.o $LIBS -o "$SRC/fuzz_$kind"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "/tmp/fuzz_$kind.o" "${OBJS[@]}" \
      /tmp/lsan_off.o /tmp/vifm_stubs.o $LIBS -o "$SRC/fuzz_$kind-standalone"
done
