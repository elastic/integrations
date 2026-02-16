ARG MSSQL_VERSION=${MSSQL_VERSION:-2019-latest}
FROM mcr.microsoft.com/mssql/server:${MSSQL_VERSION}

ENV ACCEPT_EULA='Y'
ENV SA_PASSWORD='1234_asdf'

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD /opt/mssql-tools18/bin/sqlcmd -S localhost -U SA -P ${SA_PASSWORD} -No -Q "SELECT 1" || exit 1
