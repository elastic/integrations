# Cisco ISE

The Cisco ISE integration collects and parses data from [Cisco Identity Services Engine](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) (ISE) using TCP/UDP.

## Compatibility

This module has been tested against `Cisco ISE server version 3.1.0.518`.

## Requirements

- Enable the integration with the TCP/UDP input.
- Sign in to Cisco ISE Portal.
- Configure Remote Syslog Collection Locations.
  - **Procedure**
      1. In Cisco ISE Administrator Portal, go to **Administration** > **System** > **Logging** > **Remote Logging Targets**.
      2. Click **Add**.
      ![Cisco ISE server setup image](../img/cisco-ise-setup.png)
      3. Enter all the **Required Details**.
      4. Set the maximum length to **8192**.
      5. Click **Submit**. 
      6. Go to the **Remote Logging Targets** page and verify the creation of the new target.

## Note
- It is recommended to have **8192** as Maximum Message Length. Segmentation for certain logs coming from Cisco ISE might cause issues with field mappings. 

## Logs

Reference link for Cisco ISE Syslog: [Here](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html) 

### log

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}