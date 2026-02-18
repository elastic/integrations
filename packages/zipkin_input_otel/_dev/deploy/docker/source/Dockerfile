# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod main.go .
RUN go build -o send-zipkin-traces .

# Runtime stage
FROM alpine:3.18
COPY --from=builder /app/send-zipkin-traces /send-zipkin-traces
ENTRYPOINT ["/send-zipkin-traces"]
