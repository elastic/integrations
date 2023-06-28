ARG MONGODB_VERSION=5.0
FROM mongo:${MONGODB_VERSION}
RUN apt update && yes | apt install netcat
HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 27017
