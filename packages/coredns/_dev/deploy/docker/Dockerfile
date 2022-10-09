FROM debian:stable-slim
ARG SERVICE_VERSION=${SERVICE_VERSION:-1.10.0}
SHELL [ "/bin/sh", "-ec" ]

RUN export DEBCONF_NONINTERACTIVE_SEEN=true \
           DEBIAN_FRONTEND=noninteractive \
           DEBIAN_PRIORITY=critical \
           TERM=linux ; \
    apt-get -qq update ; \
    apt-get -yyqq install ca-certificates wget; \
    apt-get clean; \
    wget https://github.com/coredns/coredns/releases/download/v${SERVICE_VERSION}/coredns_${SERVICE_VERSION}_linux_amd64.tgz;\
    tar -xvf coredns_${SERVICE_VERSION}_linux_amd64.tgz; \
    chmod +x /coredns

COPY ./files /config

EXPOSE 53 53/udp
ENTRYPOINT ["/coredns", "-conf", "/config/Corefile"]