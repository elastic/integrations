FROM golang:1.21

WORKDIR /build
COPY ./mock_server /build
RUN go build -o /mock_server .

COPY ./mongodb_atlas /data

CMD ["/mock_server"]

HEALTHCHECK --interval=1s --retries=90 CMD curl localhost:7780/api/atlas/v2/groups/mongodb-group1/processes --digest -u admin:MongoDB@123
