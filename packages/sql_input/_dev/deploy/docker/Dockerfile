FROM mysql:8.0.13

USER root
ENV MYSQL_ROOT_PASSWORD test

HEALTHCHECK --interval=10s --retries=5 CMD /healthcheck.sh

COPY healthcheck.sh /healthcheck.sh
