# Custom WMI (Windows Management Instrumentation) Input Package

The Custom WMI Input integration reads metrics via Windows Management Instrumentation  [(WMI)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/about-wmi), a core management technology in the Windows Operating system.
By leveraging WMI Query Language (WQL), this integration allows you to extract detailed system information and metrics to monitor the health and performance of Windows Systems.

This input leverages the [Microsoft WMI](https://github.com/microsoft/wmi) library, a convenient wrapper around the [GO-OLE](https://github.com/go-ole) library which allows to invoke the WMI Api.

## Requirements

This integration requires Elastic-Agent 8.19.0 or 9.1.0 and above.

## Compatibility

This integration has been tested on the following platforms:

| Operating System                            | Architecture |
|---------------------------------------------|--------------|
| Microsoft Windows Server 2019 Datacenter    | x64          |
| Microsoft Windows 11 Pro                    | x64          |


### WMI Query Language (WQL) Support

This integrations supports the execution of
[WQL](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)
queries, a SQL-like query language for retrieving information from WMI
namespaces.

Currently, the metricset supports queries with `SELECT`, `FROM` and
`WHERE` clauses.

When working with WMI queries, it is the user’s responsibility to ensure
that queries are safe, efficient, and do not cause unintended side
effects. A notorious example of a problematic WMI class is
Win32\_Product. Read more in [Windows
Documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications#more-information_).

###  WMI Arbitrator and Query Execution

Query execution is managed by the underlying WMI Framework, specifically
the [WMI
Arbitrator](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/new-wmi-arbitrator-behavior-in-windows-server).
The Arbitrator is responsible for:

- Scheduling and controlling query execution

- Throttling or stopping queries based on system resource availability
  and conditions

There is no way to directly stop a query once it has started. To prevent
Metricbeat from waiting indefinitely for a query to return a result or
fail, Metricbeat has a timeout mechanism that stops waiting for query
results after a specified timeout. This is controlled by the
`wmi.warning_threshold` setting.

While Metricbeat stops waiting for the result, the underlying WMI query
may continue running until the WMI Arbitrator decides to stop execution.



## WMI Type support

The `microsoft/wmi` library internally uses the WMI Scripting API. This API, as per the
[official WMI Documentation](https://learn.microsoft.com/en-us/windows/win32/wmisdk/querying-wmi),
does not provide direct type conversion for `uint64`, `sint64`, and `datetime`
[Common Information Model](https://learn.microsoft.com/en-us/windows/win32/wmisdk/common-information-model) (CIM) types;
instead, these values are returned as strings.

To ensure the correct data type is reported, Elastic-Agent dynamically fetches the
CIM type definitions for the properties of the WMI instance classes returned by the query,
and then performs the necessary data type conversions.

To optimize performance and avoid repeatedly fetching these schema definitions
for every row and every request, an LRU cache is utilized. This cache stores
the schema definition for each WMI class, property pair encountered. For queries involving
superclasses, such as `CIM_LogicalDevice`, the cache will populate with individual entries
for each specific derived class (leaf of the class hierarchy) whose instances are returned by the query (for example, `Win32_DiskDrive` or `Win32_NetworkAdapter`).

::::{note}
The properties of type `CIM_Object` (embedded objects) are not yet supported and are ignored.
::::

::::{note}
The properties of type `CIM_Reference` (references) used in [WMI Association Classes](https://learn.microsoft.com/en-us/windows/win32/wmisdk/declaring-an-association-class) are currently returned as strings as reported by the microsoft/wmi library.
::::


###  Date Fields Mapping

Elastic-Agent converts WMI properties of type "datetime" to timestamps, but these are serialized as strings in the output. Since date detection is disabled by default, these fields will be stored as strings unless explicitly mapped as dates. To ensure proper mapping, we recommend explicitly setting the mapping in the `@custom` template.
Refer to [this guide](https://www.elastic.co/docs/reference/fleet/data-streams#data-streams-index-templates-edit)
and [this guide](https://www.elastic.co/docs/manage-data/data-store/index-basics#manage-component-templates) for additional
details.

## Configuration


**`wmi.namespace`**
:   The default WMI namespace used for queries. This can be overridden per
query. The default is `root\cimv2`.

**`wmi.warning_threshold`**
:   The time threshold after which Metricbeat will stop waiting for the
query result and return control to the main flow of the program. A
warning is logged indicating that the query execution has exceeded the
threshold. The default is equal to the period. See [WMI Arbitrator and
Query Execution](#wmi-arbitrator-and-query-execution) for more details.

**`wmi.include_queries`**
:   If set to `true` the metricset includes the query in the output
document. The default value is `false`.

**`wmi.include_null_properties`**
:   If set to `true` the metricset includes the properties that have null
value in the output document. properties that have a `null` value in the
output document. The default value is `false`.

**`wmi.include_empty_string_properties`**
:   A boolean option that causes the metricset to include the properties
that are empty string. The default value is `false`.

**`wmi.queries`**
:   The list of queries to execute. The list cannot be empty. See [Query
Configuration](#query-configuration) for the format of the queries.

### Query Configuration

Each item in the `queries` list specifies a wmi query to perform.

**`class`**
:    The wmi class. In the query it specifies the `FROM` clause. Required

**`properties`**
:    List of properties to return. In the query it specifies the `SELECT`
clause. Set it to the empty list (default value) to retrieve all
available properties.

**`where`**
:   The where clause. In the query it specifies the `WHERE` clause. Read
more about the format [in the Windows
Documentation](https://learn.microsoft.com/en-us/windows/win32/wmisdk/where-clause).

**`namespace`**
:   The WMI Namespace for this particular query (it overwrites the
metricset’s `namespace` value)

### Example

Example WQL Query:

```sql
SELECT Name, ProcessId, WorkingSetSize
FROM Win32_Process
WHERE Name = 'lsass.exe' AND WorkingSetSize > 104857600
```

Equivalent YAML Configuration:

```yaml
- class: Win32_Process
  properties:
  - Name
  - ProcessId
  - WorkingSetSize
  where: "Name = 'lsass.exe' AND WorkingSetSize > 104857600"
```