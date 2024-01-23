# Pleasant Password Server

The Pleasant Password Server integration collects and parses DNS, DHCP, and Audit data collected from [Pleasant Password Server](https://pleasantpasswords.com/) via TCP/UDP or logfile.

## Setup steps
1. Enable the integration with TCP/UDP input.
2. Log in to the PPS WebUI.
3. Configure the PPS to send messages to a Syslog server using the following steps. 
    1. From the Menu go to Logging -> Syslog Configuration
    2. Set the Syslog Configuration to Enabled
    3. Set Hostname to the Hostname of your Fleet Agent or Load Balancer
    4. Set the Correct Port used in the Integration Configuration
    5. Set UDP or TCP
    6. Optionally set the Facility

## Compatibility

This module has been tested against `Pleasant Password Server Version 7.11.44.0 `.  
It should however work with all versions.

## Log samples
Below are the samples logs of the respective category:

## Audit Logs:
```
<134>Jan 23 09:49:10 SRV-PPS-001 Pleasant Password Server:192.168.1.2 - user@name.test -  - Success - Syslog Settings Changed - User <user@name.test> Syslogging setting updated  changing the host from <localhost> to <127.0.0.1> changing the port fr	127.0.0.1	23/01 09:49:10.894	
<134>Jan 23 11:32:57 SRV-PPS-001 Pleasant Password Server:192.168.1.2 - user@name.test -  - Success - Password Fetched - User <user@name.test> fetched the password for <TOP/SECRET/PASSWORD> - test	127.0.0.1	23/01 11:32:57.857	
<134>Jan 23 12:20:07 SRV-PPS-001 Pleasant Password Server:0.0.0.0 - Backup Restore Service -  - Success - Backup Occurred - User <Backup Restore Service> backing up database to <C:\ProgramData\Pleasant Solutions\Password Server\Backups\Backup	127.0.0.1	23/01 12:20:07.802	
<134>Jan 23 12:37:37 SRV-PPS-001 Pleasant Password Server:192.168.1.1 - user@name.test -  - Success - Session Log On - User <user@name.test> logged on	127.0.0.1	23/01 12:37:37.346
<134>Jan 23 12:38:07 SRV-PPS-001 Pleasant Password Server:192.168.1.1 - user@name.test -  - Success - Entry Updated - User <user@name.test> updated entry <TOP/SECRET/PASSWORD> changing the password	127.0.0.1	23/01 12:38:07.629	
<134>Jan 23 13:43:47 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Success - Identity Verified - User <user@name.test> verified via ApplicationBasicOAuth	127.0.0.1	23/01 13:43:47.422	
<134>Jan 23 13:47:25 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Error - Identity Not Verified - User <user@name.test> failed to verify themselves	127.0.0.1	23/01 13:47:25.593	
<134>Jan 23 13:47:25 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Error - Sign-in Failed - User <user@name.test> sign-in denied	127.0.0.1	23/01 13:47:25.641	
<134>Jan 23 14:05:54 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Success - Entry Created - User <user@name.test> created entry <TOP/SECRET/PASSWORD> as a duplicate	127.0.0.1	23/01 14:05:54.404	
<134>Jan 23 14:05:54 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Success - Entry Duplicated - User <user@name.test> duplicated entry <TOP/SECRET/PASSWORD>	127.0.0.1	23/01 14:05:54.450	
```

## Logs

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}
