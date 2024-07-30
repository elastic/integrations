#!/bin/bash
set -e

echo "Starting MySQL master..."

# Initialize and start MySQL server using the default entrypoint script
docker-entrypoint.sh mysqld &

# Wait for the master database to be ready
echo "Waiting for MySQL to be ready..."
while ! mysqladmin ping -h "127.0.0.1" --silent; do
    echo "MySQL master is not up yet..."
    sleep 2
done
echo "MySQL master is ready."

# Create replication user on the master
# Check if the replication user already exists
user_exists=$(mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1 FROM mysql.user WHERE user = 'mydb_replica_user';" -ss)
if [ -z "$user_exists" ]; then
  echo "Creating replication user..."
priv_stmt='CREATE USER "mydb_replica_user"@"%" IDENTIFIED BY "mydb_replica_pwd"; GRANT REPLICATION SLAVE ON *.* TO "mydb_replica_user"@"%"; FLUSH PRIVILEGES;'
# docker-compose exec mysql_master mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "$priv_stmt"
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "$priv_stmt"
else
  echo "Replication user already exists. Skipping user creation."
fi

# Now, keep the script running to prevent the container from exiting
wait