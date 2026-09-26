ARG NATS_VERSION=2.10.27
FROM nats:$NATS_VERSION

# build stage
FROM golang:1.25-alpine AS build-env
RUN apk --no-cache add build-base git gcc
RUN go install github.com/nats-io/nats.go/examples/nats-bench@v1.36.0
WORKDIR /src
COPY jetstream-traffic.go .
RUN go mod init jetstream-traffic && go get github.com/nats-io/nats.go@v1.36.0 && go mod tidy && CGO_ENABLED=0 go build -o /jetstream-traffic jetstream-traffic.go

# create an enhanced container with nc command available since nats is based
# on scratch image making healthcheck impossible
FROM alpine:3.20
COPY --from=0 / /opt/nats
COPY --from=build-env /go/bin/nats-bench /nats-bench
COPY --from=build-env /jetstream-traffic /jetstream-traffic
COPY run.sh /run.sh
# Expose client, management, and cluster ports
EXPOSE 4222 8222 6222
HEALTHCHECK --interval=1s --retries=30 CMD nc -w 1 0.0.0.0 8222 </dev/null
# Run via the configuration file
CMD ["/run.sh"]
