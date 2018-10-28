#!/usr/bin/zsh
set -e

test_flags() {
    echo "============================================================="
    echo "   TEST:  $1"
    echo "============================================================="
    FLAGS=(${(@s/ /)1})
    for i in $@[2,-1]
    do
        echo " --- bintail ---"
        ./bintail $FLAGS $i test-`basename $i`
        echo " --- command ---"
        ./test-`basename $i`
    done
}

samples=( `ls samples/*.c | sed 's/\.c$//'` samples/{grep,busybox})
echo "Samples: $samples"

test_flags "-d" $samples
test_flags "-a config_first -g" $samples
test_flags "-A -g" $samples
