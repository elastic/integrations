ARG MONGODB_VERSION
FROM mongo:${MONGODB_VERSION}
RUN sed -i "/jessie-updates/d" /etc/apt/sources.list
RUN apt-get update && apt-get install -y netcat
COPY init.js .
COPY adduser.js .
RUN touch /var/log/mongodb/mongod.log && \
    chown -R mongodb:mongodb /var/log/mongodb/ && \
    chmod -R 777 /var/log/mongodb/mongod.log
HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 27017