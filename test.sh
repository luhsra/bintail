#!/usr/bin/zsh
set -e

test_flags() {
    echo "============================================================="
    echo "   TEST:  $1"
    echo "============================================================="
    FLAGS=(${(@s/ /)1})
    for i in $@[2,-1]
    do
        if [[ $i == *extern-definition ]] || [[ $i == *fp-simple ]] || [[ $i == *function-pointer ]]
        then
            echo "SKIP $i"
            continue
        fi
        echo " --- bintail $i ---"
        ./bintail $FLAGS $i test-`basename $i`
        echo " --- command $i ---"
        ./test-`basename $i`
    done
}

samples=( `ls samples/*.c tests/*.c | sed 's/\.c$//'` samples/{grep,busybox})
echo "Samples: $samples"

test_flags "-d" $samples
test_flags "-a config_first -g" $samples
test_flags "-A -g" $samples
