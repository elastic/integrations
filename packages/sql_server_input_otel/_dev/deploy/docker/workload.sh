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

# Background: holds an exclusive table lock for 20s, causing the foreground SELECTs to block.
# Blocked sessions appear in sys.dm_exec_requests as status=suspended with a real query hash,
# making them reliably visible to the query_sample collector across each collection interval.
while true; do
    $SQLCMD -Q "BEGIN TRAN; SELECT * FROM dbo.test_table WITH (TABLOCKX, HOLDLOCK); WAITFOR DELAY '00:00:20'; ROLLBACK;" >/dev/null 2>&1
done &

# Foreground: repeated short queries for top_query capture
while true; do
    $SQLCMD -Q "SELECT * FROM dbo.test_table" >/dev/null 2>&1
    sleep 1
done
