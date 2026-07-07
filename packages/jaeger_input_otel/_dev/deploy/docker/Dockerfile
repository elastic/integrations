FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY sender/ .
RUN go mod download && go build -o /jaeger-trace-sender .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /jaeger-trace-sender /usr/local/bin/jaeger-trace-sender
ENTRYPOINT ["/usr/local/bin/jaeger-trace-sender"]
