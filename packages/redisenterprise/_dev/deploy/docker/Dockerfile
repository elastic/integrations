ARG REDISENTERPRISE_VERSION
FROM redislabs/redis:${REDISENTERPRISE_VERSION:-5.4.10-22}

# Wait for the health endpoint to have monitors information
ADD healthcheck.sh /
HEALTHCHECK --interval=1s --retries=300 CMD /healthcheck.sh
