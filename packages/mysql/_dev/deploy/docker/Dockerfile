ARG IMAGE=${IMAGE}
FROM ${IMAGE}

USER root
ENV MYSQL_ROOT_PASSWORD test

HEALTHCHECK --interval=1s --retries=90 CMD /healthcheck.sh

COPY healthcheck.sh /healthcheck.sh
COPY entrypoint.sh /test-entrypoint.sh

RUN chmod +x /healthcheck.sh
RUN chmod +x /test-entrypoint.sh

ENTRYPOINT ["bash", "/test-entrypoint.sh"]
