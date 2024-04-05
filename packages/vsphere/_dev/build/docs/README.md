# VMware vSphere Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility
The integration uses the [Govmomi](https://github.com/vmware/govmomi) library to collect metrics and logs from any Vmware SDK URL (ESXi/VCenter). This library is built for and tested against ESXi and vCenter 6.5, 6.7 and 7.0.

## Metrics

To access the metrices, the url https://host:port(8989)/sdk needs to be passed to the hosts in Kibana UI. 

### Virtual Machine Metrics

 The virtual machine consists of a set of specification and configuration files and is backed by the physical resources of a host. Every virtual machine has virtual devices that provide the same functionality as physical hardware but are more portable, secure and easier to manage.

 Note: vSphere Integration currently supports network names of VMs connected only to vSS (vSphere Standard Switch) and not vDS (vSphere Distributed Switches).

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

To collect logs, a syslog daemon is used. First, you must configure the listening host/IP address (default: localhost) and host port (default: 9525) in the integration. Then, configure vSphere to send logs to a remote syslog host and provide the configured hostname/IP and port of the Elastic Agent host.

### vSphere Logs

{{fields "log"}}
