CREATE USER IF NOT EXISTS 'mydb_replica_user'@'%' IDENTIFIED BY 'mydb_replica_pwd';
GRANT REPLICATION SLAVE ON *.* TO 'mydb_replica_user'@'%';
GRANT REPLICATION CLIENT ON *.* TO 'mydb_replica_user'@'%';
CREATE USER IF NOT EXISTS 'spec_user'@'%' IDENTIFIED BY 'p@ss:w#rd!';
GRANT REPLICATION CLIENT ON *.* TO 'spec_user'@'%';
FLUSH PRIVILEGES;