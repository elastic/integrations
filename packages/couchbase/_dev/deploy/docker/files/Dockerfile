FROM golang:1.18
WORKDIR /usr/src/
RUN git clone https://github.com/couchbaselabs/couchbase-sync-gateway-exporter.git
WORKDIR /usr/src/couchbase-sync-gateway-exporter/
RUN git checkout 9272038aae7fd46575befda06449f008f41b6b01
RUN go build -v -o /usr/local/bin/app .
CMD ["app","--log.level=debug","--sgw.url=http://sgw:4985"]
