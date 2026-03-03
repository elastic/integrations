FROM mysql:8.0.35
ENV MYSQL_ROOT_PASSWORD=111
COPY entrypoint-master.sh /entrypoint-master.sh
RUN chmod +x /entrypoint-master.sh
ENTRYPOINT ["/entrypoint-master.sh"]
CMD ["mysqld"]