ARG IMAGE=${IMAGE:-mysql:5.7.34}
FROM ${IMAGE}

ENV MYSQL_ROOT_PASSWORD test

HEALTHCHECK --interval=1s --retries=90 CMD /healthcheck.sh

COPY healthcheck.sh /healthcheck.sh
COPY entrypoint.sh /test-entrypoint.sh

ENTRYPOINT ["bash", "/test-entrypoint.sh"]
