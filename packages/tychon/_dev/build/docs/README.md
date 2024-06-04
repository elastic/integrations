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

{{fields "tychon_arp"}}

### Vulnerablities

TYCHON scans for Endpoint CPU's and returns the results.

{{fields "tychon_cpu"}}

### Vulnerablities

TYCHON scans for Endpoint vulnerablities and returns the results.

{{fields "tychon_cve"}}

### Endpoint Protection Platform

TYCHON scans the Endpoint's Windows Defender and returns protection status and version details.

{{fields "tychon_epp"}}

### Endpoint Exposed Services Information

The TYCHON script to scan Endpoint Exposed Services and returns information.

{{fields "tychon_exposedservice"}}

### Endpoint Hard Drive Information

The TYCHON script scans an endpoint's Hard Drive Configurations and returns information.

{{fields "tychon_harddrive"}}

### Endpoint Hardware Information

The TYCHON script scans an endpoint's Hardware Configurations and returns information.

{{fields "tychon_hardware"}}

### Endpoint Host OS Information

The TYCHON script scans an endpoint's OS Configurations and returns information.

{{fields "tychon_host"}}

### Endpoint Network Adapters Information

The TYCHON script scans an endpoint's Network Adapter Configurations and returns information.

{{fields "tychon_networkadapter"}}

### Endpoint Software Inventory Information

The TYCHON script scans an endpoint's Software Inventory and returns information.

{{fields "tychon_softwareinventory"}}

### Endpoint STIG Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.

{{fields "tychon_stig"}}

### Endpoint Volume Information

The TYCHON script scans an endpoint's Volume Configurations and returns information.

{{fields "tychon_volume"}}

### Windows Feature Information

TYCHON gathers which Windows features have been enabled on endpoints and returns the results.

{{fields "tychon_features"}}

### COAMS Information (DATT Required)

TYCHON has integtred with DISA DATT and gathering what Operational Attributes have been applied.

{{fields "tychon_coams"}}

### File System Certificates 

TYCHON searches the computer and hard drive for certificate files that stored in a keystore and outside of a keystore.

{{fields "tychon_systemcerts"}}

### Listening Certificate Ciphers

TYCHON connects to open ports on the computer and reports back if it is hosting ciphers and the certificate information from those ciphers.

{{fields "tychon_ciphers"}}

### Browser Configurations

TYCHON checks local browser configuration settings.

{{fields "tychon_browser"}}
