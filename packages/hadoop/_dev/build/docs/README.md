# Hadoop

This integration is used to collect [Hadoop](https://hadoop.apache.org/) metrics as follows:

   - Application Metrics
   - Cluster Metrics
   - DataNode Metrics
   - NameNode Metrics
   - NodeManager Metrics   

This integration uses Resource Manager API and JMX API to collect above metrics.

## application

This data stream collects Application metrics.

{{event "application"}}

{{fields "application"}}

## cluster

This data stream collects Cluster metrics.

{{event "cluster"}}

{{fields "cluster"}}

## datanode

This data stream collects Datanode metrics.

{{event "datanode"}}

{{fields "datanode"}}

## namenode

This data stream collects Namenode metrics.

{{event "namenode"}}

{{fields "namenode"}}
## node_manager

This data stream collects Node Manager metrics.

{{event "node_manager"}}

{{fields "node_manager"}}
