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
