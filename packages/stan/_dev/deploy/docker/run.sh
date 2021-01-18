#!/bin/bash

/nats-streaming-server -DV -l /var/log/stan/stan.log -m 8222 &
sleep 2
while true; do /stan-bench -np 0 -ns 100 -qgroup T -n 100000000 -ms 1024 foo; done
#while true; do /stan-bench -np 10 -ns 10 -n 1000000000 -ms 1024 bar; done &

# Make sure the container keeps running
tail -f /dev/null

