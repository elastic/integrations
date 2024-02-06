# Fortinet FortiManager Integration

The [Fortinet FortiManager](https://fortimanager.forticloud.com/) integration allows you to monitor logs sent in the syslog format.
Fortinet FortiManager is the Network Operations Center (NOC) and a Security Operations Center (SOC) operations tool that was built with a security perspective. It provides a single-pane-of-glass across the entire Fortinet Security Fabric.

The Fortinet FortiManager integration can be used in three different input modes:
- Filestream mode: It read lines from active log files. To configure this input, specify a list of glob-based paths that must be crawled to locate and fetch the log lines.
- TCP mode: Fortinet FortiManager pushes logs directly to a TCP port hosted by your Elastic Agent.
- UDP mode: Fortinet FortiManager pushes logs directly to a UDP port hosted by your Elastic Agent.

## Data streams

The Fortinet FortiManager integration collects logs for different subtypes of events:

  | FortiManager                                   | FortiAnalyzer                  |
  | -----------------------------------------------| -------------------------------|
  | System Manager (system)                        | Log Files (logfile)            |
  | FortiGuard Service (fgd)                       | Logging Status (logging)       |
  | Security Console (scply)                       | Logging Device (logdev)        |
  | Firmware Manager (fmwmgr)                      | Logging Database (logdb)       |
  | Log Daemon (logd)                              | FortiAnalyzer System (fazsys)  |
  | Debug IO Log (iolog)                           | Reports (report)               |
  | FortiGate-FortiManager Protocol (fgfm)         |                                |
  | Device Manager (devmgr/dvm)                    |                                |
  | Deployment Manager (dm)                        |                                |
  | Object Changes (objcfg)                        |                                |
  | Script Manager (scrmgr)                        |                                |

**NOTE**: As per the log availability, we are only supporting the event subtypes given in above table. For more details, look into [Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf).

## Compatibility

This integration has been tested against FortiManager & FortiAnalyzer **7.2.2**. Versions above this are expected to work but have not been tested.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

Follow this [Fortinet FortiManager VM Install Guide](https://help.fortinet.com/fmgr/vm-install/56/Resources/HTML/0000_OnlineHelp%20Cover.htm)

## Log Reference

The `log` dataset collects Fortinet FortiManager logs.

{{event "log"}}

{{fields "log"}}
