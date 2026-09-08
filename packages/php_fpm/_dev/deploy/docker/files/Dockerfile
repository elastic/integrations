FROM bitnamilegacy/php-fpm:8.1.31-debian-12-r2

# Following command enables "/status" endpoint

RUN echo >> /opt/bitnami/php/etc/php-fpm.d/www.conf &&\
    echo "pm.status_path = /status" >> /opt/bitnami/php/etc/php-fpm.d/www.conf

# Following command installs nginx

RUN apt-get update -y &&\
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx &&\
    rm -rf /var/lib/apt/lists/*

COPY ./default /etc/nginx/sites-enabled/default
COPY ./entrypoint.sh /home/entrypoint.sh
RUN chmod 777 /home/entrypoint.sh -R

CMD ["/bin/bash","-c","/home/entrypoint.sh"]
