# TYCHON Agentless

[TYCHON Agentless](https://tychon.io/products/tychon-agentless/) is an integration that lets you collect TYCHON's gold source vulnerability and STIG data from endpoints without heavy resource use or software installation. You can then investigate the TYCHON data using Elastic's analytics, visualizations, and dashboards. [Contact us to learn more.](https://tychon.io/start-a-free-trial/) 

## Compatibility

* This integration supports Windows 10 and Windows 11 Endpoint Operating Systems. 
* This integration requires a TYCHON Agentless license. 
* This integration requires [TYCHON Vulnerability Definition](https://support.tychon.io/) files.


## Returned Data Fields
### ARP Table Information

TYCHON scans Endpoint ARP Tables and returns the results.  

**Exported fields**
{{fields "tychon_arp"}}

### Vulnerablities

TYCHON scans for Endpoint CPU's and returns the results.  

**Exported fields**
{{fields "tychon_cpu"}}

### Vulnerablities

TYCHON scans for Endpoint vulenrabilites and returns the results.  

**Exported fields**
{{fields "tychon_cve"}}

### Endpoint Protection Platform

TYCHON scans the Endpoint's Windows Defender and returns protection status and version details.  

**Exported fields**
{{fields "tychon_epp"}}

### Endpoint Exposed Services Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_exposedservice"}}

### Endpoint Hard Drive Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_harddrive"}}

### Endpoint Hardware Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_hardware"}}

### Endpoint Host OS Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_host"}}

### Endpoint Network Adapters Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_networkadapter"}}

### Endpoint Software Inventory Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_softwareinventory"}}

### Endpoint STIG Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_stig"}}

### Endpoint Volume Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_volume"}}
