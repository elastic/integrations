# Oracle 

[Oracle](https://www.oracle.com) Oracle package fetches metrics from an Oracle database instance.

## Compatibility
Oracle package is being tested with version 12c R2 by using the store/oracle/database-enterprise:12.2.0.1 Docker 
image downloaded directly from the [Oracle Docker Hub repository](https://hub.docker.com/_/oracle-database-enterprise-edition)
which is based on 5.0.13-arch1-1-ARCH Arch Linux.

OCI Instant Client is also required and the module has been tested by using version 18.5. See below for more information.

## Requirements
Oracle database requires a special OCI connector to get connected to the database. You can find more information about 
it in the [official link of Oracle's webpage](https://www.oracle.com/database/technologies/instant-client.html). Oracle's 
webpage contains a comprehensive manual about installation methods and troubleshooting. A small description is included 
here but follow Oracle's official documentation if you find some issue. The OCI Instant Client is available with the 
Oracle Universal Installer, RPM file or ZIP file. Download links can be found [here](https://www.oracle.com/database/technologies/instant-client/downloads.html). The Oracle Technology Network License Agreement with Oracle must be accepted to download the library.

The OCI library install few Client Shared Libraries that must be referenced on the machine where the Agent is installed. 
The environment variable `LD_LIBRARY_PATH` is used to set the reference required by the library. For example, 
let's say you have downloaded the library into your `Downloads` folder, you can follow the steps below to install the ZIP 
library on `/usr/lib` (assuming you have `wget` and a zip unpacker):

```bash
unzip $HOME/Downloads/instantclient-basic-linux.x64-18.5.0.0.0dbru.zip -d /usr/lib
export LD_LIBRARY_PATH=/usr/lib/instantclient_18_5:$LD_LIBRARY_PATH`
```

## Metrics

### Tablespaces

Includes information about data files and temp files, grouped by Tablespace with free space available, used space, 
status of the data files, status of the Tablespace, etc.

#### Required database permissions

To ensure that the module has access to the appropriate metrics, the module requires that you configure a user with 
access to the following tables:

* `SYS.DBA_TEMP_FILES`
* `DBA_TEMP_FREE_SPACE`
* `dba_data_files`
* `dba_free_space`

### Performance
Includes performance related events that might be correlated between them. It contains mainly cursor and cache based 
data and can generate 3 types of events.

#### Required database permissions

To ensure that the package has access to the appropriate metrics, it requires that you configure a user with access to 
the following tables:

* `V$BUFFER_POOL_STATISTICS`
* `v$sesstat`
* `v$statname`
* `v$session`
* `v$sysstat`
* `V$LIBRARYCACHE`