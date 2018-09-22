#!/bin/sh

eu-readelf -S $1 | head -n4
eu-readelf -S $1 | tail -n+5 | sort -k 5
