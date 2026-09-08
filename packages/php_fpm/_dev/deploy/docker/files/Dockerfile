FROM bitnamilegacy/php-fpm:8.1.12-debian-11-r4

# Following command enables "/status" endpoint

RUN echo >> /opt/bitnami/php/etc/php-fpm.d/www.conf &&\
    echo "pm.status_path = /status" >> /opt/bitnami/php/etc/php-fpm.d/www.conf

# Debian 11 LTS ended 31 Aug 2026. bullseye-security InRelease is expired and
# its pool 404s, so use archive.debian.org and skip the security repo.
RUN printf 'deb http://archive.debian.org/debian bullseye main\ndeb http://archive.debian.org/debian bullseye-updates main\n' > /etc/apt/sources.list && \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until && \
    apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/*

COPY ./default /etc/nginx/sites-enabled/default
COPY ./entrypoint.sh /home/entrypoint.sh
RUN chmod 777 /home/entrypoint.sh -R

CMD ["/bin/bash","-c","/home/entrypoint.sh"]
