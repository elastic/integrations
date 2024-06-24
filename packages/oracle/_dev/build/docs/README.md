# Oracle Integration

This integration is for ingesting Audit Trail logs and fetching performance, tablespace and sysmetric metrics from Oracle Databases.

The integration expects an *.aud audit file that is generated from Oracle Databases by default. If this has been disabled then please see the [Oracle Database Audit Trail Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html#GUID-8D96829C-9151-4FA4-BED9-831D088F12FF).

### Requirements

Connectivity to Oracle can be facilitated in two ways either by using official Oracle libraries or by using a JDBC driver. Facilitation of the connectivity using JDBC is not supported currently with Metricbeat. Connectivity can be facilitated using Oracle libraries and the detailed steps to do the same are mentioned below.

#### Oracle Database Connection Pre-requisites

To get connected with the Oracle Database ORACLE_SID, ORACLE_BASE, ORACLE_HOME environment variables should be set.

For example: Let’s consider Oracle Database 21c installation using RPM manually by following the [Oracle Installation instructions](https://docs.oracle.com/en/database/oracle/oracle-database/21/ladbi/running-rpm-packages-to-install-oracle-database.html). Environment variables should be set as follows:
    `ORACLE_SID=ORCLCDB`
    `ORACLE_BASE=/opt/oracle/oradata`
    `ORACLE_HOME=/opt/oracle/product/21c/dbhome_1`
Also, add `$ORACLE_HOME/bin` to the `PATH` environment variable.

#### Oracle Instant Client

Oracle Instant Client enables development and deployment of applications that connect to Oracle Database. The Instant Client libraries provide the necessary network connectivity and advanced data features to make full use of Oracle Database. If you have OCI Oracle server which comes with these libraries pre-installed, you don't need a separate client installation.

The OCI library install few Client Shared Libraries that must be referenced on the machine where Metricbeat is installed. Please follow the [Oracle Client Installation link](https://docs.oracle.com/en/database/oracle/oracle-database/21/lacli/install-instant-client-using-zip.html#GUID-D3DCB4FB-D3CA-4C25-BE48-3A1FB5A22E84) link for OCI Instant Client set up. The OCI Instant Client is available with the Oracle Universal Installer, RPM file or ZIP file. Download links can be found at the [Oracle Instant Client Download page](https://www.oracle.com/database/technologies/instant-client/downloads.html).

If Elastic Agent is running as a systemd service and not using `ldconfig` is an option, to update the links to the shared libraries, you can use the `LD_LIBRARY_PATH` environment variable instead. Follow these steps to ensure Elastic Agent and its spawned processes respect the `LD_LIBRARY_PATH` environment variable.

> Prerequisites: Ensure that you have administrative privileges to modify the Elastic Agent systemd service configuration.

Steps:
1. Check the status of the Elastic Agent systemd service by running the following command:
   `systemctl status elastic-agent.service`
   Take note of the path to the elastic-agent.service file, which is typically located in the systemd service directory. Example path: `/etc/systemd/system/elastic-agent.service`

2. Open the elastic-agent.service file in your preferred text editor, find the `EnvironmentFile` key (commonly found at `/etc/sysconfig/elastic-agent`), and verify its contents, as these configurations are essential for the elastic-agent's runtime environment initialization. If the EnvironmentFile is absent, create it and set the necessary permissions to ensure the elastic-agent has full access.  

3. Add the LD_LIBRARY_PATH environment variable to the configured `EnvironmentFile`. You can set it to the directory where libraries (`libclntsh.so`) are located. For example, if your libraries are in the `/opt/oracle/instantclient_21_1 directory`, add the following line to the `EnvironmentFile` (i.e. `/etc/systemd/system/elastic-agent.service`)

      `LD_LIBRARY_PATH=/opt/oracle/instantclient_21_1`

4. Save the changes made to the configured `EnvironmentFile`.

5. Restart the Elastic Agent systemd service to apply the changes by running the following command:

      `systemctl restart elastic-agent.service`

> Note: Ensure that you replace `/opt/oracle/instantclient_21_1` with the actual path to the directory where the required libraries (`libclntsh.so`) are located. This will set the library search path for the Elastic Agent service to include the specified directory, allowing it to locate the required libraries.

####  Enable Listener

The Oracle listener is a service that runs on the database host and receives requests from Oracle clients. Make sure that [Listener](https://docs.oracle.com/cd/B19306_01/network.102/b14213/lsnrctl.htm) is be running. 
To check if the listener is running or not, run: 

`lsnrctl STATUS`

If the listener is not running, use the command to start:

`lsnrctl START`

Then, Metricbeat can be launched.

### Oracle DSN Configuration

The following two configuration formats are supported:
```
oracle://<user>:<password>@<connection_string>
user="<user>" password="<password>" connectString="<connection_string>" sysdba=<true|false>
```

Example values are:
```
oracle://sys:Oradoc_db1@0.0.0.0:1521/ORCLCDB.localdomain?sysdba=1
user="sys" password="Oradoc_db1" connectString="0.0.0.0:1521/ORCLCDB.localdomain" sysdba=true
```

In the first, URL-based format, special characters should be URL encoded.

In the seoncd, logfmt-encoded DSN format, if the password contains a backslash
character (`\`), it must be escaped with another backslash. For example, if the
password is `my\_password`, it must be written as `my\\_password`.

> Note: To mask the password shown in the DSN, remove the username and password from the DSN string, and configure the DSN to only include the host address and any additional parameters required for the connection. Subsquently, use the `username` and `password` fields under advanced options to configure them. 

## Compatibility

This integration has been tested with Oracle Database 19c, and should work for 18c as well though it has not been tested.

### Audit Log

The `database_audit` dataset collects Oracle Audit logs.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "database_audit"}}

{{event "database_audit"}}

### Tablespace Metrics

Tablespace metrics describes the tablespace usage metrics of all types of tablespaces in the oracle database.

To collect the Tablespace metrics, Oracle integration relies on a specific set of views. Make sure that the user configured within the Oracle DSN configuration has `READ` access permissions to the following views:
 
- `SYS.DBA_DATA_FILES`
- `SYS.DBA_TEMP_FILES`
- `DBA_FREE_SPACE`

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "tablespace"}}

{{event "tablespace"}}

### Sysmetrics 

The system metrics value captured for the most current time interval for the long duration (60-seconds) are listed in the following table. 

To collect the Sysmetrics metrics, Oracle integration relies on a specific set of views. Make sure that the user configured within the Oracle DSN configuration has `READ` access permissions to the following view:

- `V$SYSMETRIC`

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "sysmetric"}}

{{event "sysmetric"}}

### Memory Metrics 

A Program Global Area (PGA) is a memory region that contains data and control information for a server process. It is nonshared memory created by Oracle Database when a server process is started. Access to the PGA is exclusive to the server process. Metrics concerning Program Global Area (PGA) memory are mentioned below.

To collect the Memory metrics, Oracle integration relies on a specific set of views. Make sure that the user configured within the Oracle DSN configuration has `READ` access permissions to the following views:

- `V$SGASTAT`
- `V$PGASTAT`

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "memory"}}

{{event "memory"}}

### System Statistics Metrics 

The System Global Area (SGA) is a group of shared memory structures that contain data and control information for one Oracle Database instance. Metrics concerning System Global Area (SGA) memory are mentioned below.

To collect the System Statistics metrics, Oracle integration relies on a specific set of views. Make sure that the user configured within the Oracle DSN configuration has `READ` access permissions to the following view:

- `V$SYSSTAT`

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system_statistics"}}

{{event "system_statistics"}}

### Performance Metrics

Performance metrics give an overview of where time is spent in the system and enable comparisons of wait times across the system.

To collect the Performance metrics, Oracle integration relies on a specific set of views. Make sure that the user configured within the Oracle DSN configuration has `READ` access permissions to the following views:

- `V$BUFFER_POOL_STATISTICS`
- `V$SESSTAT`
- `V$SYSSTAT`
- `V$LIBRARYCACHE`
- `DBA_JOBS`
- `GV$SESSION`
- `V$SYSTEM_WAIT_CLASS`

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "performance"}}

{{event "performance"}}
