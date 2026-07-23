#!/bin/bash

TIMEOUT=60

if [ -x /opt/mssql-tools18/bin/sqlcmd ]; then
    SQLCMD="/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U SA -P $SA_PASSWORD -No"
else
    SQLCMD="/opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P $SA_PASSWORD"
fi

for ((i=0; i<TIMEOUT; i++)); do
    $SQLCMD -Q "SELECT 1" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        break
    fi
    sleep 1
done

set -euo pipefail

$SQLCMD -Q "IF DB_ID('testdb') IS NULL CREATE DATABASE testdb;"

$SQLCMD -d testdb -Q "
IF OBJECT_ID('dbo.test_table', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.test_table (
        id INT PRIMARY KEY IDENTITY(1,1),
        name NVARCHAR(100)
    );
END;
INSERT INTO dbo.test_table (name) VALUES (N'Hello World'), (N'Test Entry');
"

touch /tmp/init_done
echo "Initialization complete."
