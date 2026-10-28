FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY generator/ .
RUN go mod download && go build -o /generator .

FROM alpine:3.21
COPY --from=builder /generator /usr/local/bin/generator
ENTRYPOINT ["/usr/local/bin/generator"]
