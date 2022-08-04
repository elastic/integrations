# VMware vSphere Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility
The integration uses the [Govmomi](https://github.com/vmware/govmomi) library to collect metrics and logs from any Vmware SDK URL (ESXi/VCenter). This library is built for and tested against ESXi and vCenter 6.5, 6.7 and 7.0.

## Metrics

To access the metrices, the url https://host:port(8989)/sdk needs to be passed to the hosts in Kibana UI. 

### Virtual Machine Metrics

 The virtual machine consists of a set of specification and configuration files and is backed by the physical resources of a host. Every virtual machine has virtual devices that provide the same functionality as physical hardware but are more portable, secure and easier to manage.

{{event "virtualmachine"}}

{{fields "virtualmachine"}}

### Host Metrics

 ESX hosts are the servers/data storage devices on which the ESX or ESXi hypervisor has been installed. One of these hosts can support multiple VMs

{{event "host"}}

{{fields "host"}}

### Datastore Metrics
Datastores are logical containers, analogous to file systems, that hide specifics of physical storage and provide a uniform model for storing virtual machine files. 
{{event "datastore"}}

{{fields "datastore"}}

## Logs

To access the logs, host address (localhost) and host port (9525) needs to be passed in Kibana UI. 

### vSphere Logs

{{fields "log"}}
