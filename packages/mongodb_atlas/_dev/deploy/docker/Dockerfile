FROM golang:1.20

WORKDIR /app

COPY ./mongodb_atlas .

RUN go mod download

CMD ["go","run","main.go"]
