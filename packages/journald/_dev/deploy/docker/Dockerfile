FROM debian:stable-slim

RUN apt-get update \
      && apt install -y systemd-journal-remote \
      && rm -rf /var/lib/apt/lists/*