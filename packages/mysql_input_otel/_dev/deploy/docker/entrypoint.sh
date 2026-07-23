#!/bin/sh
set -e
/usr/local/bin/docker-entrypoint.sh mysqld &
until mysql -u root -e "SELECT 1" 2>/dev/null; do sleep 2; done
mysql -u root -e "GRANT SELECT ON performance_schema.* TO 'root'@'%'; FLUSH PRIVILEGES;" 2>/dev/null || true
WORKLOAD_STARTED=0
trap 'WORKLOAD_STARTED=1' HUP
echo "Waiting for SIGHUP to start workload..."
while [ "$WORKLOAD_STARTED" -eq 0 ]; do sleep 1; done
echo "SIGHUP received, starting workload..."
while true; do
  mysql -u root -e "SELECT 1; SELECT SLEEP(2); SELECT COUNT(*) FROM information_schema.tables;"
  sleep 1
done
