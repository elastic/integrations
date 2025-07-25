ARG SERVICE_VERSION=${SERVICE_VERSION:-2.4.46}
FROM httpd:$SERVICE_VERSION
RUN sed -i 's/deb.debian/archive.debian/' /etc/apt/sources.list && \
    sed -i 's/security.debian/archive.debian/' /etc/apt/sources.list && \
    sed -i "/buster-updates/d" /etc/apt/sources.list
RUN apt-get update && apt-get install -y curl
HEALTHCHECK --interval=1s --retries=90 CMD curl -f http://localhost
COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf