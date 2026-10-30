ARG VSPHERE_GOLANG_VERSION

FROM golang:${VSPHERE_GOLANG_VERSION}-alpine

RUN apk add --no-cache curl git
# vcsim is its own Go module with a replace directive, so `go install .../vcsim@<version>` fails.
RUN git clone --depth 1 --branch v0.56.2 https://github.com/vmware/govmomi /src/govmomi \
    && cd /src/govmomi/vcsim && go build -o /go/bin/vcsim . \
    && rm -rf /src/govmomi /root/.cache/go-build

HEALTHCHECK --interval=1s --retries=60 --timeout=10s CMD curl http://localhost:8989/
CMD vcsim -pod 1 -l :8989
