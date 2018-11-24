#!/usr/bin/zsh
set -e

test_flags() {
    echo "============================================================="
    echo "   TEST:  $1"
    echo "============================================================="
    FLAGS=(${(@s/ /)1})
    for i in $@[2,-1]
    do
        echo " --- bintail $i ---"
        ./bintail $FLAGS $i test-`basename $i`
        echo " --- command $i ---"
        ./test-`basename $i`
    done
}

samples=( `ls samples/*.c | sed 's/\.c$//'`)
echo "Samples: $samples"

test_flags "-d" $samples
test_flags "-a config_first" $samples
test_flags "-A" $samples
