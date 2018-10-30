#!/usr/bin/zsh

cd _measure

echo " === Full Apply and Guard === "
rm *-patched

for f in ./*
do
    echo "$f & $(../bintail -A $f $f-patched)"
done

echo " === Check Guard === "
for g in ./*-patched
do
    echo "$g $(../callsite-check.py $g)"
done
