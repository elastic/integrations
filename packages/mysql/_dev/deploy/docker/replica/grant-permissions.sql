CREATE USER IF NOT EXISTS 'mydb_replica_user'@'%' IDENTIFIED BY 'mydb_replica_pwd';
GRANT REPLICATION CLIENT ON *.* TO 'mydb_replica_user'@'%';
FLUSH PRIVILEGES;