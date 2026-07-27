# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN go build -ldflags="-s -w" -o /app .

# Run stage
FROM alpine:3.22
COPY --from=builder /app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
