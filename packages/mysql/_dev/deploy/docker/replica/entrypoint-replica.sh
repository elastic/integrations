#!/bin/bash
set -e

echo "Starting MySQL slave..."

# Start the MySQL server in the background
docker-entrypoint.sh mysqld &

# Wait for the slave database to be ready
echo "Waiting for MySQL to be ready..."
while ! mysqladmin ping -h "127.0.0.1" --silent; do
    echo "MySQL slave is not up yet..."
    sleep 2
done
echo "MySQL slave is ready."

# Configure the slave to start replication
echo "Configuring slave to start replication..."
# Wait for the master to be ready and for its logs to be available
MASTER_LOGS_AVAILABLE=false
for i in {1..30}; do
  echo "Attempt $i: Checking master status..."
  MS_STATUS=$(mysql -h "$MYSQL_MASTER_HOST" -P 3306 -u root -p"$MYSQL_ROOT_PASSWORD" -e "SHOW MASTER STATUS;" 2>/dev/null || echo "FAILED")

  if [ "$MS_STATUS" = "FAILED" ]; then
    echo "Failed to connect to master, retrying..."
    sleep 2
    continue
  fi

  echo "Master status: $MS_STATUS"

  CURRENT_LOG=$(echo "$MS_STATUS" | awk 'NR==2 {print $1}')
  CURRENT_POS=$(echo "$MS_STATUS" | awk 'NR==2 {print $2}')

  echo "Debug: CURRENT_LOG = '$CURRENT_LOG'"
  echo "Debug: CURRENT_POS = '$CURRENT_POS'"

  if [ -n "$CURRENT_LOG" ] && [ -n "$CURRENT_POS" ]; then
    MASTER_LOGS_AVAILABLE=true
    break
  else
    echo "Waiting for master logs to be available..."
    sleep 2
  fi
done

if [ "$MASTER_LOGS_AVAILABLE" = false ]; then
    echo "Failed to obtain master log file and position."
    exit 1
fi

echo "Master status obtained. Current log: '$CURRENT_LOG', Current position: '$CURRENT_POS'."

# Validate the values
if [ -z "$CURRENT_LOG" ] || [ -z "$CURRENT_POS" ]; then
  echo "Error: Empty log file or position values"
  exit 1
fi

# Reset the slave to ensure a clean replication setup
echo "Resetting the slave..."
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "STOP SLAVE; RESET SLAVE ALL;" 2>/dev/null || echo "Slave was not running"


mysql -uroot -p"$MYSQL_ROOT_PASSWORD" <<EOF
CHANGE MASTER TO 
  MASTER_HOST='$MYSQL_MASTER_HOST',
  MASTER_USER='mydb_replica_user',
  MASTER_PASSWORD='mydb_replica_pwd',
  MASTER_LOG_FILE='$CURRENT_LOG',
  MASTER_LOG_POS=$CURRENT_POS;
EOF

if [ $? -eq 0 ]; then
    echo "CHANGE MASTER command executed successfully"

    # Start the slave
    mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "START SLAVE;"

    if [ $? -eq 0 ]; then
      echo "Slave started successfully"
    else
      echo "Failed to start slave"
      exit 1
    fi
else
  echo "Failed to execute CHANGE MASTER command"
  exit 1
fi

# Verify slave status
echo "Verifying slave status..."
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SHOW SLAVE STATUS \G"

# Now, keep the script running to prevent the container from exiting
tail -f /dev/null