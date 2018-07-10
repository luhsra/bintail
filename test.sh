#!/usr/bin/zsh
set -e

mkdir -p _tmp
cd _tmp

test_flags() {
    echo "============================================================="
    echo "   TEST:  $1"
    echo "============================================================="
    FLAGS=(${(@s/ /)1})
    for i in $@[2,-1]
    do
        echo "-> $i"
        cp $i edit
        ../bintail -f edit -dylr > before.txt
        ../bintail -f edit $FLAGS > out.txt
        ../bintail -f edit -dylr > after.txt
        ./edit > prog.txt
    done
}

samples=( `ls ../samples/*.c | sed 's/\.c$//'` )
echo "Samples: $samples"

test_flags "-a config_first -w -t" $samples
test_flags "-s config_first=0 -w -t" $samples
