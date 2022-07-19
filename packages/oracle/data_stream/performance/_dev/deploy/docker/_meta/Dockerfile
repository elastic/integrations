FROM docker.elastic.co/observability-ci/database-enterprise:12.2.0.1

# RUN apt update && apt install -y libaio1


# COPY instantclient.zip ./ 

# RUN unzip instantclient.zip && \
# mv instantclient_21_6/ /usr/lib/ && \
# mv instantclient_21_6/ /usr/lib/ && \
# rm instantclient.zip && \
# ln /usr/lib/instantclient_12_1/libclntsh.so.12.1 /usr/lib/libclntsh.so && \
# ln /usr/lib/instantclient_12_1/libocci.so.12.1 /usr/lib/libocci.so && \
# ln /usr/lib/instantclient_12_1/libociei.so /usr/lib/libociei.so && \
# ln /usr/lib/instantclient_12_1/libnnz12.so /usr/lib/libnnz12.so


# ENV ORACLE_BASE /usr/lib/instantclient_12_1
# ENV LD_LIBRARY_PATH /usr/lib/instantclient_12_1
# ENV TNS_ADMIN /usr/lib/instantclient_12_1
# ENV ORACLE_HOME /usr/lib/instantclient_12_1

HEALTHCHECK --interval=5s --retries=90 CMD /usr/bin/echo 'select 1' | /u01/app/oracle/product/12.2.0/dbhome_1/bin/sqlplus sys/Oradoc_db1@localhost:1521/ORCLPDB1.localdomain AS SYSDBA
