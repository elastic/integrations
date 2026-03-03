FROM ubuntu:20.04

RUN apt-get update \
      && apt install -y systemd-journal-remote \
      && rm -rf /var/lib/apt/lists/*