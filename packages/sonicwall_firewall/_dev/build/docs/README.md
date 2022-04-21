# SonicWall Firewall Integration

This integration collects syslog messages from SonicWall firewalls. It has been tested with SonicOS 6.5 and 7.0.

## Configuration

Configure a Syslog Server in your firewall using the following options:
 - **Name or IP Address:** The address where your Elastic Agent running this integration is reachable.
 - **Port:** The Syslog port (UDP) configured in this integration.
 - **Server Type:** Syslog Server.
 - **Syslog Format:** Enhanced Syslog.
 - **Syslog ID:** Change this default (`firewall`) if you need to differentiate between multiple firewalls.
                  This value will be stored in the `observer.name` field. 

It's recommended to enable the **Display UTC in logs (instead of local time)** setting under the
_Device > Settings > Time_ configuration menu. Otherwise you'll have to configure the **Timezone Offset**
setting of this integration to match the timezone configured in your firewall.

Ensure proper connectivity between your firewall and Elastic Agent.

## Logs

{{event "log"}}

{{fields "log"}}