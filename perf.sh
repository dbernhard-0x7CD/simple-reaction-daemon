#!/bin/sh
./srd &
srd_pid=$!
perf record -F 9999 -g -p $srd_pid
perf script > out.perf
stackcollapse-perf.pl out.perf > perf.data_collapsed
flamegraph.pl perf.data_collapsed > out.svg
