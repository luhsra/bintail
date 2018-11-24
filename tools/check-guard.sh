#!/bin/sh

./callsite-check.py _measure/bintail-bss-nolib-patched
./callsite-check.py _measure/bintail-mvcommit-patched
./callsite-check.py _measure/bintail-no-lib-patched
./callsite-check.py _measure/bintail-simple-patched
./callsite-check.py _measure/busybox-patched
./callsite-check.py _measure/grep-patched
./callsite-check.py _measure/multiverse-commit-refs-patched
./callsite-check.py _measure/multiverse-enums-patched
./callsite-check.py _measure/multiverse-enums-simple-patched
./callsite-check.py _measure/multiverse-guess-integral-value-patched
./callsite-check.py _measure/multiverse-invalid-value-patched
./callsite-check.py _measure/multiverse-mvfn-reduction-patched
./callsite-check.py _measure/multiverse-one-variable-gcc-bool-patched
./callsite-check.py _measure/multiverse-one-variable-patched
./callsite-check.py _measure/multiverse-revert-patched
./callsite-check.py _measure/multiverse-special-mvfns-patched
./callsite-check.py _measure/multiverse-tracked-patched
./callsite-check.py _measure/multiverse-user-values-patched
