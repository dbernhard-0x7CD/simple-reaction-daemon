#!/bin/bash

# This script runs ./srd for exactly $1 seconds and prints the user/kernel times 

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [runtime in seconds]"
    exit 0
fi


run_bench () {
  time ./srd &
  time_pid=$!

  # now search for the time pid and get the pid for srd
  srd_pid=$(ps -af | grep -A 1 $time_pid | grep "./srd" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
  
  # sleep the runtime
  sleep $1

  kill -SIGTERM $srd_pid
  echo "Ran ./srd for $1 seconds."
}

run_bench $1

