#!/bin/bash

for i in `ls tests/*.c | sed 's/\.c$//'`; do
    echo "bintail $i" >&2
    ./bintail $i
done
