FROM ubuntu:20.04

RUN apt-get -o Acquire::Retries=3 update \
      && apt-get install -y systemd-journal-remote \
      && rm -rf /var/lib/apt/lists/*
