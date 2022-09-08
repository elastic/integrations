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

####  Enable Listener

The Oracle listener is a service that runs on the database host and receives requests from Oracle clients. Make sure that [Listener](https://docs.oracle.com/cd/B19306_01/network.102/b14213/lsnrctl.htm) is be running. 
To check if the listener is running or not, run: 

`lsnrctl STATUS`

If the listener is not running, use the command to start:

`lsnrctl START`

Then, Metricbeat can be launched.

*Host Configuration*

The following two types of host configurations are supported:

1. Old style host configuration for backwards compatibility:
    - `hosts: ["user/pass@0.0.0.0:1521/ORCLPDB1.localdomain"]`
    - `hosts: ["user/password@0.0.0.0:1521/ORCLPDB1.localdomain as sysdba"]`

2. DSN host configuration:
    - `hosts: ['user="user" password="pass" connectString="0.0.0.0:1521/ORCLPDB1.localdomain"']`
    - `hosts: ['user="user" password="password" connectString="host:port/service_name" sysdba=true']`


Note: If the password contains the backslash (`\`) character, it must be escaped with a backslash. For example, if the password is `my\_password`, it should be written as `my\\_password`.


## Compatibility

This integration has been tested with Oracle Database 19c, and should work for 18c as well though it has not been tested.

### Audit Log

The `database_audit` dataset collects Oracle Audit logs.

{{fields "database_audit"}}

{{event "database_audit"}}

### Performance Metrics

{{fields "performance"}}

{{event "performance"}}

### Tablespace Metrics

{{fields "tablespace"}}

{{event "tablespace"}}

### Sysmetrics 

{{fields "sysmetric"}}

{{event "sysmetric"}}
