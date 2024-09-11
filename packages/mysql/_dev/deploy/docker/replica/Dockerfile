FROM mysql:8.0.35
ENV MYSQL_ROOT_PASSWORD=111
COPY entrypoint-replica.sh /entrypoint-replica.sh
COPY grant-permissions.sql /docker-entrypoint-initdb.d/
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /healthcheck.sh
RUN chmod +x /entrypoint-replica.sh
ENTRYPOINT ["/entrypoint-replica.sh"]
CMD ["mysqld"]