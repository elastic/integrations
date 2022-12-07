FROM bitnami/php-fpm:8.1.12-debian-11-r4

# Following command enables "/status" endpoint

RUN echo >> /opt/bitnami/php/etc/php-fpm.d/www.conf &&\
    echo "pm.status_path = /status" >> /opt/bitnami/php/etc/php-fpm.d/www.conf

# Following command installs nginx

RUN apt-get update -y &&\
    apt-get upgrade -y &&\
    apt-get install nginx -y

COPY ./default /etc/nginx/sites-enabled/default
COPY ./entrypoint.sh /home/entrypoint.sh
RUN chmod 777 /home/entrypoint.sh -R

CMD ["/bin/bash","-c","/home/entrypoint.sh"]
