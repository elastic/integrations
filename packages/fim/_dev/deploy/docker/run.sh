#!/bin/sh
log() {
  echo "$@" >&2
}
signal_fired() {
  done=1
}
wait_for_signal() {
  while test $done -eq 0
  do
    sleep 1
  done
}
done=0
trap signal_fired HUP
log Waiting for signal
wait_for_signal
log Performing test actions
echo hello world > shared/hello
sleep 2
rm shared/hello
touch shared/done
