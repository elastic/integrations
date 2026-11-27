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

# The signal is sent when the agent policy is assigned, before the input is
# watching. Each metricset starts after a random delay of up to
# auditbeat.max_start_delay (10s by default), and the agent may take a few
# seconds to start the input, so wait long enough for the watcher to be
# running. Otherwise the actions below happen before the input can see them.
log Waiting for the input to start watching
sleep 15

log Performing test actions
echo hello world > shared/hello
sleep 2
rm shared/hello
touch shared/done
