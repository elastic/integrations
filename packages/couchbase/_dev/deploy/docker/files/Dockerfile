FROM golang:1.18 AS builder
WORKDIR /usr/src/couchbase-sync-gateway-exporter/
RUN git init && \
    git fetch --depth 1 https://github.com/couchbaselabs/couchbase-sync-gateway-exporter.git 9272038aae7fd46575befda06449f008f41b6b01 && \
    git checkout FETCH_HEAD && \
    CGO_ENABLED=0 go build -v -o /usr/local/bin/app .

FROM alpine:3.18
RUN apk add --no-cache curl ca-certificates
COPY --from=builder /usr/local/bin/app /usr/local/bin/app
CMD ["app","--log.level=debug","--sgw.url=http://sgw:4985"]
