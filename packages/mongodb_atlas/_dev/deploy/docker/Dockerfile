FROM golang:1.19

COPY ./mongodb_atlas /go
CMD ["./test"]

HEALTHCHECK --interval=1s --retries=90 CMD curl localhost:7780/api/atlas/v2/groups/mongodb-group1/processes --digest -u admin:MongoDB@123