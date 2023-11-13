# TYCHON Agentless

[TYCHON Agentless](https://tychon.io/products/tychon-agentless/) is an integration that lets you collect TYCHON's gold source Master Endpoint Record  data from endpoints, including vulnerability and STIG results, without heavy resource use or software installation. You can then investigate the TYCHON data using Elastic's analytics, visualizations, and dashboards. [Contact us to learn more.](https://tychon.io/start-a-free-trial/) 

## Compatibility

* This integration supports Windows and RedHat/CENTOS Endpoint Operating Systems. 
* This integration requires a TYCHON Agentless license. 
* This integration requires [TYCHON Vulnerability Definition](https://support.tychon.io/) files.
* The Linux Endpoint requires RedHat's [OpenScap](https://www.open-scap.org/tools/openscap-base/) to be installed for STIG and CVE to report data.
* This integration supports Elastic 8.8+.

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

TYCHON scans for Endpoint vulnerablities and returns the results.  

**Exported fields**
{{fields "tychon_cve"}}

### Endpoint Protection Platform

TYCHON scans the Endpoint's Windows Defender and returns protection status and version details.  

**Exported fields**
{{fields "tychon_epp"}}

### Endpoint Exposed Services Information

The TYCHON script to scan Endpoint Exposed Services and returns information.  

**Exported fields**
{{fields "tychon_exposedservice"}}

### Endpoint Hard Drive Information

The TYCHON script scans an endpoint's Hard Drive Configurations and returns information.  

**Exported fields**
{{fields "tychon_harddrive"}}

### Endpoint Hardware Information

The TYCHON script scans an endpoint's Hardware Configurations and returns information.  

**Exported fields**
{{fields "tychon_hardware"}}

### Endpoint Host OS Information

The TYCHON script scans an endpoint's OS Configurations and returns information.  

**Exported fields**
{{fields "tychon_host"}}

### Endpoint Network Adapters Information

The TYCHON script scans an endpoint's Network Adapter Configurations and returns information.  

**Exported fields**
{{fields "tychon_networkadapter"}}

### Endpoint Software Inventory Information

The TYCHON script scans an endpoint's Software Inventory and returns information.  

**Exported fields**
{{fields "tychon_softwareinventory"}}

### Endpoint STIG Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
{{fields "tychon_stig"}}

### Endpoint Volume Information

The TYCHON script scans an endpoint's Volume Configurations and returns information.  

**Exported fields**
{{fields "tychon_volume"}}
