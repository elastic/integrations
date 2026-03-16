#!/bin/bash

SERVER="sql_server_input_otel"
PASSWORD="1234_asdf"
DATABASE="testdb"

if [ -x /opt/mssql-tools18/bin/sqlcmd ]; then
    SQLCMD="/opt/mssql-tools18/bin/sqlcmd -C -S $SERVER -U SA -P $PASSWORD -No -d $DATABASE"
else
    SQLCMD="/opt/mssql-tools/bin/sqlcmd -S $SERVER -U SA -P $PASSWORD -d $DATABASE"
fi

echo "Waiting for $SERVER to be ready..."
for i in $(seq 1 60); do
    $SQLCMD -Q "SELECT 1" >/dev/null 2>&1 && break
    sleep 1
done

echo "Starting workload generation..."
touch /tmp/workload_ready

# Background: long-running query for query_sample capture
while true; do
    $SQLCMD -Q "WAITFOR DELAY '00:00:30'; SELECT * FROM dbo.test_table" >/dev/null 2>&1
done &

# Foreground: repeated short queries for top_query capture
while true; do
    $SQLCMD -Q "SELECT * FROM dbo.test_table" >/dev/null 2>&1
    sleep 1
done
