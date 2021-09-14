# VMware vSphere Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility

The vSphere metrics datasets were tested with VMware vCenter 6.7.0.31000 and vSphere (ESXi) 6.7.0 Update 1 (Build 10764712) and are expected to work with all versions >= 6.7. The log dataset was tested on VMware vCenter 6.7.0.31000 and is expected to work with all versions >= 6.7.

## Logs

### vSphere Logs

{{fields "log"}}

## Metrics

### Virtual Machine Metrics

{{event "virtualmachine"}}

{{fields "virtualmachine"}}

### Host Metrics

{{event "host"}}

{{fields "host"}}

### Datastore Metrics

{{event "datastore"}}

{{fields "datastore"}}