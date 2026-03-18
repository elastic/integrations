ARG NGINX_SERVICE_VERSION=${NGINX_SERVICE_VERSION:-1.28.2}
FROM nginx:${NGINX_SERVICE_VERSION}
RUN if [ "${NGINX_SERVICE_VERSION}" = "1.19.5" ]; then \
      sed -i 's/deb.debian/archive.debian/' /etc/apt/sources.list && \
      sed -i 's/security.debian/archive.debian/' /etc/apt/sources.list && \
      sed -i "/buster-updates/d" /etc/apt/sources.list && \
      apt-get update && apt-get install -y curl; \
    else \
      echo "Skipping Debian archive APT rewrite for nginx:${NGINX_SERVICE_VERSION}"; \
    fi
HEALTHCHECK --interval=1s --retries=90 CMD curl -f http://localhost/server-status
COPY ./nginx.conf /etc/nginx/
