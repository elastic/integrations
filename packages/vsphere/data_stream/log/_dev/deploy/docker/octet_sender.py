"""Send a log file as RFC 6587 octet-counted syslog frames (MSG-LEN SP SYSLOG-MSG, no newline) over TCP.

Usage: octet_sender.py HOST PORT FILE. Sending starts after SIGHUP.
"""
import signal
import socket
import sys
import time

host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
started = False


def on_hup(*_):
    global started
    started = True


signal.signal(signal.SIGHUP, on_hup)
while not started:
    time.sleep(0.2)
time.sleep(5)

for _ in range(30):
    try:
        conn = socket.create_connection((host, port), timeout=5)
        break
    except OSError:
        time.sleep(2)
else:
    sys.exit(f"cannot connect to {host}:{port}")

with open(path, encoding="utf-8") as f:
    for line in f:
        msg = line.rstrip("\n").encode("utf-8")
        if msg:
            conn.sendall(str(len(msg)).encode() + b" " + msg)

# ESX keeps the connection open, so the input must split frames without waiting for EOF.
while True:
    time.sleep(3600)
