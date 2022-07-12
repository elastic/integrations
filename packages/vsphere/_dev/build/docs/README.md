# VMware vSphere Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility

The vSphere metrics datasets were tested with VMware vCenter 6.7.0.31000 and vSphere (ESXi) 6.7.0 Update 1 (Build 10764712) and are expected to work with all versions >= 6.7. The log dataset was tested on VMware vCenter 6.7.0.31000 and is expected to work with all versions >= 6.7.

## Metrics

### Virtual Machine Metrics
 The virtual machine consists of a set of specification and configuration files and is backed by the physical resources of a host. Every virtual machine has virtual devices that provide the same functionality as physical hardware but are more portable, secure and easier to manage.

{{event "virtualmachine"}}

{{fields "virtualmachine"}}

### Host Metrics

 ESX hosts are the servers/data storage devices on which the ESX or ESXi hypervisor has been installed. The use of hypervisors such as ESX and ESXi to create VMs (virtualization) is highly efficient, as one host device can support multiple VMs

{{event "host"}}

{{fields "host"}}

### Datastore Metrics
Datastores are logical containers, analogous to file systems, that hide specifics of physical storage and provide a uniform model for storing virtual machine files. 
{{event "datastore"}}

{{fields "datastore"}}

## Logs
### vSphere Logs

{{fields "log"}}