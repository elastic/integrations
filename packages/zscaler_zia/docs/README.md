# Zscaler ZIA

This integration is for [Zscaler](https://help.zscaler.com/zia/documentation-knowledgebase/authentication-administration) Internet Access logs. It can be used
to receive logs sent by NSS log server on respective TCP ports.

The log message is expected to be in JSON format. The data is mapped to ECS fields where applicable and the remaining fields are written under `zscaler_zia.<data-stream-name>.*`.

## Steps for setting up NSS Feeds

1. Enable the integration with the TCP input.
2. Configure the Zscaler NSS Server and NSS Feeds to send logs to the Elastic Agent that is running this integration. See [Add NSS Server](https://help.zscaler.com/zia/adding-nss-servers) and [Add NSS Feeds](https://help.zscaler.com/zia/adding-nss-feeds). Use the IP address hostname of the Elastic Agent as the 'NSS Feed SIEM IP Address/FQDN', and use the listening port of the Elastic Agent as the 'SIEM TCP Port' on the _Add NSS Feed_ configuration screen. To configure Zscaler NSS Server and NSS Feeds follow the following steps.
    - In the ZIA Admin Portal, add an NSS Server.
        - Log in to the ZIA Admin Portal using your admin account. If you're unable to log in, [contact Support](https://www.zscaler.com/company/contact).
        - Add an NSS server. Refer to Adding NSS Servers to set up an [Add NSS Server](https://help.zscaler.com/zia/adding-nss-servers) for Web and/or Firewall.
        - Verify that the state of the NSS Server is healthy.
            - In the ZIA Admin Portal, go to Administration > Nanolog Streaming Service > NSS Servers.
            - In the State column, confirm that the state of the NSS server is healthy.
            ![NSS server setup image](../img/nss_server.png?raw=true)
    - In the ZIA Admin Portal, add an NSS Feed.
        - Refer to [Add NSS Feeds](https://help.zscaler.com/zia/adding-nss-feeds) and select the type of feed you want to configure. The following fields require specific inputs:
            - **SIEM IP Address**: Enter the IP address of the [Elastic agent](https://www.elastic.co/guide/en/fleet/current/fleet-overview.html) you’ll be assigning the Zscaler integration to.
            - **SIEM TCP Port**: Enter the port number, depending on the logs associated with the NSS Feed. You will need to create an NSS Feed for each log type.
                - **Alerts**: 9010
                - **DNS**: 9011
                - **Firewall**: 9012
                - **Tunnel**: 9013
                - **Web**: 9014
            - **Feed Output Type**: Select Custom in Feed output type and paste the appropriate response format in Feed output format as follows:
            ![NSS Feeds setup image](../img/nss_feeds.png?raw=true)

## Steps for setting up Cloud NSS Feeds

1. Enable the integration with the HTTP Endpoint input.
2. Configure the Zscaler Cloud NSS Feeds to send logs to the Elastic Agent that is running this integration. Provide API URL to send logs to the Elastic Agent. To configure Zscaler Cloud NSS Feeds follow the following steps.
    - In the ZIA Admin Portal, add a Cloud NSS Feed.
        - Log in to the ZIA Admin Portal using your admin account.
        - Add a Cloud NSS Feed. See to [Add Cloud NSS Feed](https://help.zscaler.com/zia/adding-cloud-nss-feeds).
          - In the ZIA Admin Portal, go to Administration > Nanolog Streaming Service > Cloud NSS Feeds.
          - Give Feed Name, change status to Enabled.
          - Select NSS Type.
          - Change SIEM Type to other.
          - Add an API URL.
          - Default ports:
              - **DNS**: 9556
              - **Firewall**: 9557
              - **Tunnel**: 9558
              - **Web**: 9559
          - Select JSON as feed output type.
          - Add same custom header along with its value on both the side for additional security.
          ![Cloud NSS Feeds setup image](../img/cloud_nss_feeds.png?raw=true)
3. Repeat step 2 for each log type.

**Please make sure to use the given response formats for NSS and Cloud NSS Feeds.**

Note: Please make sure to use latest version of given response formats.

## Compatibility

This package has been tested against `Zscaler Internet Access version 6.1`

## Documentation and configuration

### Alerts

- Default port (NSS Feed): _9010_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/about-alerts)

Zscaler response format (v1):
```
<%d{syslogid}>%s{Monthname} %2d{Dayofmonth} %02d{Hour}:%02d{Minutes}:%02d{Seconds} [%s{Deviceip}] ZscalerNSS: %s{Eventinfo}\n
```

Sample Response:
```
<114>Dec 10 14:04:28 [175.16.199.1] ZscalerNSS: Zscaler cloud configuration connection to  175.16.199.1:443 lost and unavailable for the past 2325.00 minutes
```

### DNS Log

- Default port (NSS Feed): _9011_
- Default port (Cloud NSS Feed): _9556_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-dns-logs)

Zscaler response format (v1):
```
\{ "sourcetype" : "zscalernss-dns", "event" :\{"datetime":"%s{time}","user":"%s{elogin}","department":"%s{edepartment}","location":"%s{elocation}","reqaction":"%s{reqaction}","resaction":"%s{resaction}","reqrulelabel":"%s{reqrulelabel}","resrulelabel":"%s{resrulelabel}","dns_reqtype":"%s{reqtype}","dns_req":"%s{req}","dns_resp":"%s{res}","srv_dport":"%d{sport}","durationms":"%d{durationms}","clt_sip":"%s{cip}","srv_dip":"%s{sip}","category":"%s{domcat}","deviceowner":"%s{deviceowner}","devicehostname":"%s{devicehostname}"\}\}
```

Sample Response:
```json
{ "sourcetype" : "zscalernss-dns", "event" :{"datetime":"Fri Dec 17 07:27:54 2021","user":"some_user@example.com","department":"Unknown","location":"TestLoc%20DB","reqaction":"REQ_ALLOW","resaction":"Some Response Action","reqrulelabel":"Access%20Blocked","resrulelabel":"None","dns_reqtype":"Some type","dns_req":"example.com","dns_resp":"Some response string","srv_dport":"8080","durationms":"123456","clt_sip":"81.2.69.193","srv_dip":"81.2.69.144","category":"Professional Services","deviceowner":"Owner77","devicehostname":"Machine9000"}}
```

### Firewall Log

- Default port (NSS Feed): _9012_
- Default port (Cloud NSS Feed): _9557_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-firewall-logs)

Zscaler response format (v1):
```
\{ "sourcetype" : "zscalernss-fw", "event" :\{"datetime":"%s{time}","user":"%s{elogin}","department":"%s{edepartment}","locationname":"%s{elocation}","cdport":"%d{cdport}","csport":"%d{csport}","sdport":"%d{sdport}","ssport":"%d{ssport}","csip":"%s{csip}","cdip":"%s{cdip}","ssip":"%s{ssip}","sdip":"%s{sdip}","tsip":"%s{tsip}","tunsport":"%d{tsport}","tuntype":"%s{ttype}","action":"%s{action}","dnat":"%s{dnat}","stateful":"%s{stateful}","aggregate":"%s{aggregate}","nwsvc":"%s{nwsvc}","nwapp":"%s{nwapp}","proto":"%s{ipproto}","ipcat":"%s{ipcat}","destcountry":"%s{destcountry}","avgduration":"%d{avgduration}","rulelabel":"%s{erulelabel}","inbytes":"%ld{inbytes}","outbytes":"%ld{outbytes}","duration":"%d{duration}","durationms":"%d{durationms}","numsessions":"%d{numsessions}","ipsrulelabel":"%s{ipsrulelabel}","threatcat":"%s{threatcat}","threatname":"%s{ethreatname}","deviceowner":"%s{deviceowner}","devicehostname":"%s{devicehostname}"\}\}
```

Sample Response:
```json
{ "sourcetype" : "zscalernss-fw", "event" :{"datetime":"Fri Dec 17 07:27:54 2021","user":"some_user@example.com","department":"Unknown","locationname":"TestLoc%20DB","cdport":443,"csport":55018,"sdport":443,"ssport":0,"csip":"0.0.0.0","cdip":"0.0.0.0","ssip":"0.0.0.0","sdip":"0.0.0.0","tsip":"0.0.0.0","tunsport":0,"tuntype":"ZscalerClientConnector","action":"Drop","dnat":"No","stateful":"Yes","aggregate":"No","nwsvc":"HTTPS","nwapp":"http","proto":"TCP","ipcat":"Test Name","destcountry":"Ireland","avgduration":486,"rulelabel":"Access%20Blocked","inbytes":19052,"outbytes":1734,"duration":0,"durationms":486,"numsessions":1,"ipsrulelabel":"None","threatcat":"None","threatname":"None","deviceowner":"admin77","devicehostname":"Machine9000"}}
```

### Tunnel Log

- Default port (NSS Feed): _9013_
- Default port (Cloud NSS Feed): _9558_

See: [Zscaler Vendor documentation]( https://help.zscaler.com/zia/nss-feed-output-format-tunnel-logs)

Zscaler response format (v1):
- Tunnel Event:
    ```
    \{ "sourcetype" : "zscalernss-tunnel", "event" : \{"datetime":"%s{datetime}","Recordtype":"%s{tunnelactionname}","tunneltype":"%s{tunneltype}","user":"%s{vpncredentialname}","location":"%s{elocationname}","sourceip":"%s{sourceip}","destinationip":"%s{destvip}","sourceport":"%d{srcport}","event":"%s{event}","eventreason":"%s{eventreason}","recordid":"%d{recordid}"\}\}
    ```
- Sample Event:
    ```
    \{ "sourcetype" : "zscalernss-tunnel", "event" : \{"datetime":"%s{datetime}","Recordtype":"%s{tunnelactionname}","tunneltype":"%s{tunneltype}","user":"%s{vpncredentialname}","location":"%s{elocationname}","sourceip":"%s{sourceip}","destinationip":"%s{destvip}","sourceport":"%d{srcport}","txbytes":"%lu{txbytes}","rxbytes":"%lu{rxbytes}","dpdrec":"%d{dpdrec}","recordid":"%d{recordid}"\}\}
    ```
- IKE Phase 1
    ```
    \{ "sourcetype" : "zscalernss-tunnel", "event" : \{"datetime":"%s{datetime}","Recordtype":"%s{tunnelactionname}","tunneltype":"IPSEC IKEV %d{ikeversion}","user":"%s{vpncredentialname}","location":"%s{elocationname}","sourceip":"%s{sourceip}","destinationip":"%s{destvip}","sourceport":"%d{srcport}","destinationport":"%d{dstport}","lifetime":"%d{lifetime}","ikeversion":"%d{ikeversion}","spi_in":"%lu{spi_in}","spi_out":"%lu{spi_out}","algo":"%s{algo}","authentication":"%s{authentication}","authtype":"%s{authtype}","recordid":"%d{recordid}"\}\}
    ```
- IKE Phase 2
    ```
    \{ "sourcetype" : "zscalernss-tunnel", "event" : \{"datetime":"%s{datetime}","Recordtype":"%s{tunnelactionname}","tunneltype":"IPSEC IKEV %d{ikeversion}","user":"%s{vpncredentialname}","location":"%s{elocationname}","sourceip":"%s{sourceip}","destinationip":"%s{destvip}","sourceport":"%d{srcport}","sourceportstart":"%d{srcportstart}","destinationportstart":"%d{destportstart}","srcipstart":"%s{srcipstart}","srcipend":"%s{srcipend}","destinationipstart":"%s{destipstart}","destinationipend":"%s{destipend}","lifetime":"%d{lifetime}","ikeversion":"%d{ikeversion}","lifebytes":"%d{lifebytes}","spi":"%d{spi}","algo":"%s{algo}","authentication":"%s{authentication}","authtype":"%s{authtype}","protocol":"%s{protocol}","tunnelprotocol":"%s{tunnelprotocol}","policydirection":"%s{policydirection}","recordid":"%d{recordid}"\}\}
    ```

Sample Response:
```json
{ "sourcetype" : "zscalernss-tunnel", "event" : {"datetime":"Thu Dec 30 11:40:27 2021","Recordtype":"IPSec Phase1","tunneltype":"IPSEC IKEV 2","user":"81.2.69.145","location":"some-location","sourceip":"81.2.69.145","destinationip":"81.2.69.143","sourceport":"500","destinationport":"500","lifetime":"0","ikeversion":"2","spi_in":"00000000000000000000","spi_out":"11111111111111111111","algo":"AES-CBS","authentication":"HMAC-SHA1-96","authtype":"PSK","recordid":"1111111111111111111"}}
```

### Web Log

- Default port (NSS Feed): _9014_
- Default port (Cloud NSS Feed): _9559_
- Add characters **"** and **\\** in **feed escape character** while configuring Web Log.

![Escape feed setup image](../img/escape_feed.png?raw=true)
See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-web-logs)

Zscaler response format (v2):
```
\{ "sourcetype" : "zscalernss-web", "event" :\{"time":"%s{time}","login":"%s{login}","proto":"%s{proto}","eurl":"%s{eurl}","action":"%s{action}","appname":"%s{appname}","appclass":"%s{appclass}","reqsize":"%d{reqsize}","respsize":"%d{respsize}","stime":"%d{stime}","ctime":"%d{ctime}","urlclass":"%s{urlclass}","urlsupercat":"%s{urlsupercat}","urlcat":"%s{urlcat}","malwarecat":"%s{malwarecat}","threatname":"%s{threatname}","riskscore":"%d{riskscore}","dlpeng":"%s{dlpeng}","dlpdict":"%s{dlpdict}","location":"%s{location}","dept":"%s{dept}","cip":"%s{cip}","cintip":"%s{cintip}","sip":"%s{sip}","reqmethod":"%s{reqmethod}","respcode":"%s{respcode}","eua":"%s{eua}","ereferer":"%s{ereferer}","ruletype":"%s{ruletype}","rulelabel":"%s{rulelabel}","contenttype":"%s{contenttype}","unscannabletype":"%s{unscannabletype}","deviceowner":"%s{deviceowner}","devicehostname":"%s{devicehostname}"\}\}
```

Sample Response:
```json
{ "sourcetype" : "zscalernss-web", "event" :{"time":"Fri Dec 17 07:04:57 2021","login":"test@example.com","proto":"HTTP_PROXY","eurl":"browser.events.data.msn.com:443","action":"Blocked","appname":"General Browsing","appclass":"General Browsing","reqsize":"600","respsize":"65","stime":"0","ctime":"0","urlclass":"Business Use","urlsupercat":"Information Technology","urlcat":"Web Search","malwarecat":"None","threatname":"None","riskscore":"0","dlpeng":"None","dlpdict":"None","location":"Test DB","dept":"Unknown","cip":"192.168.2.200","cintip":"203.0.113.5","sip":"81.2.69.145","reqmethod":"CONNECT","respcode":"200","eua":"Windows%20Microsoft%20Windows%2010%20Pro%20ZTunnel%2F1.0","ereferer":"None","ruletype":"FwFilter","rulelabel":"Zscaler Proxy Traffic","contenttype":"Other","unscannabletype":"None","deviceowner":"administrator1","devicehostname":"TestMachine35"}}
```

Caveats:

- To ensure that URLs are processed correctly, logs which have a `network.protocol` value that is not `http` or `https` will be implicitly converted to `https` for the purposes of URL parsing. The original value of `network.protocol` will be preserved.

## Logs reference

### alerts

This is the `alerts` dataset.

#### Example

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2023-12-10T13:40:32.000Z",
    "agent": {
        "ephemeral_id": "5c0cb248-af87-474e-8d23-b1aff073b046",
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "zscaler_zia.alerts",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.193",
        "ip": "81.2.69.193",
        "port": 9012
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "zscaler_zia.alerts",
        "ingested": "2023-10-31T04:14:35Z"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.48.4:39300"
        },
        "syslog": {
            "priority": 114
        }
    },
    "message": "ZscalerNSS: SIEM Feed connection \"DNS Logs Feed\" to 81.2.69.193:9012 lost and unavailable for the past 2440.00 minutes",
    "related": {
        "ip": [
            "81.2.69.193"
        ]
    },
    "tags": [
        "forwarded",
        "zscaler_zia-alerts"
    ],
    "zscaler_zia": {
        "alerts": {
            "connection_lost_minutes": 2440,
            "log_feed_name": "DNS Logs Feed"
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zia.alerts.connection_lost_minutes | Amount of time after loosing connection to a server in Minutes. | double |
| zscaler_zia.alerts.log_feed_name | Name of the NSS log feed. | keyword |


### dns

This is the `dns` dataset.

#### Example

An example event for `dns` looks as following:

```json
{
    "@timestamp": "2021-12-31T02:22:22.000Z",
    "agent": {
        "ephemeral_id": "a6e6df94-aa01-4448-84b4-30c50a0c53bb",
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "zscaler_zia.dns",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "0.0.0.0",
        "port": 0
    },
    "dns": {
        "answers": {
            "name": "NotFound"
        },
        "question": {
            "name": "Unknown",
            "type": "NotFound"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zia.dns",
        "duration": 34000000000,
        "ingested": "2023-10-31T04:16:42Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "dns"
    },
    "related": {
        "hosts": [
            "Unknown",
            "NotFound"
        ],
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "Unknown"
        ]
    },
    "source": {
        "ip": "0.0.0.0"
    },
    "tags": [
        "forwarded",
        "zscaler_zia-dns"
    ],
    "user": {
        "name": [
            "Unknown"
        ]
    },
    "zscaler_zia": {
        "dns": {
            "department": "Unknown",
            "dom": {
                "category": "Other"
            },
            "duration": {
                "milliseconds": 34000
            },
            "location": "Unknown",
            "request": {
                "action": "None",
                "rule": {
                    "label": "None"
                }
            },
            "response": {
                "action": "None",
                "rule": {
                    "label": "None"
                }
            }
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zia.dns.department | Department of the user. | keyword |
| zscaler_zia.dns.dom.category | URL Category of the FQDN in the DNS request. | keyword |
| zscaler_zia.dns.duration.milliseconds | Duration of the DNS request in milliseconds. | long |
| zscaler_zia.dns.hostname | N/A | keyword |
| zscaler_zia.dns.location | Gateway location or sub-location of the source. | keyword |
| zscaler_zia.dns.request.action | Name of the action that was applied to the DNS request. | keyword |
| zscaler_zia.dns.request.rule.label | Name of the rule that was applied to the DNS request. | keyword |
| zscaler_zia.dns.response.action | Name of the action that was applied to the DNS response. | keyword |
| zscaler_zia.dns.response.rule.label | Name of the rule that was applied to the DNS response. | keyword |


### firewall

This is the `firewall` dataset.

#### Example

An example event for `firewall` looks as following:

```json
{
    "@timestamp": "2022-12-31T02:22:22.000Z",
    "agent": {
        "ephemeral_id": "2694ce14-7959-4978-81ec-be095160dbb2",
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "zscaler_zia.firewall",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 0,
        "ip": "0.0.0.0",
        "port": 0
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "outofrange",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zia.firewall",
        "duration": 0,
        "ingested": "2023-10-31T04:18:52Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "application": "NotAvailable",
        "protocol": "none",
        "transport": "ip"
    },
    "related": {
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "Unknown"
        ]
    },
    "rule": {
        "name": [
            "None"
        ]
    },
    "source": {
        "bytes": 0,
        "ip": "0.0.0.0",
        "port": 0
    },
    "tags": [
        "forwarded",
        "zscaler_zia-firewall"
    ],
    "user": {
        "name": [
            "Unknown"
        ]
    },
    "zscaler_zia": {
        "firewall": {
            "aggregate": "No",
            "client": {
                "destination": {
                    "ip": "0.0.0.0",
                    "port": 120
                }
            },
            "department": "Unknown",
            "duration": {
                "avg": 0,
                "milliseconds": 0,
                "seconds": 0
            },
            "ip_category": "Other",
            "location": {
                "name": "Unknown"
            },
            "nat": "No",
            "server": {
                "source": {
                    "ip": "0.0.0.0",
                    "port": 0
                }
            },
            "session": {
                "count": 1
            },
            "stateful": "Yes",
            "threat": {
                "category": "None",
                "name": "None"
            },
            "tunnel": {
                "ip": "0.0.0.0",
                "port": 0,
                "type": "OutOfRange"
            }
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zia.firewall.aggregate |  | keyword |
| zscaler_zia.firewall.client.destination.ip | Client destination IP address. For aggregated sessions, this is the client destination IP address of the last session in the aggregate. | ip |
| zscaler_zia.firewall.client.destination.port | Client destination port. For aggregated sessions, this is the client destination port of the last session in the aggregate. | long |
| zscaler_zia.firewall.department | Department of the user. | keyword |
| zscaler_zia.firewall.duration.avg | Average session duration, in milliseconds, if the sessions were aggregated. | long |
| zscaler_zia.firewall.duration.milliseconds | Session or request duration in milliseconds. | long |
| zscaler_zia.firewall.duration.seconds | Average session duration, in milliseconds, if the sessions were aggregated. | long |
| zscaler_zia.firewall.hostname |  | keyword |
| zscaler_zia.firewall.ip_category | URL category that corresponds to the server IP address. | keyword |
| zscaler_zia.firewall.location.name | Name of the location from which the session was initiated. | keyword |
| zscaler_zia.firewall.nat | Indicates if the destination NAT policy was applied. | keyword |
| zscaler_zia.firewall.server.source.ip | Server source IP address. For aggregated sessions, this is the server source IP address of the last session in the aggregate. | ip |
| zscaler_zia.firewall.server.source.port | Server source port. For aggregated sessions, this is the server source port of the last session in the aggregate. | long |
| zscaler_zia.firewall.session.count | Number of sessions that were aggregated. | double |
| zscaler_zia.firewall.stateful |  | keyword |
| zscaler_zia.firewall.threat.category | Category of the threat in the Firewall session by the IPS engine. | keyword |
| zscaler_zia.firewall.threat.name | Name of the threat detected in the Firewall session by the IPS engine. | keyword |
| zscaler_zia.firewall.tunnel.ip | Tunnel IP address of the client (source). For aggregated sessions, this is the client's tunnel IP address corresponding to the last session in the aggregate. | ip |
| zscaler_zia.firewall.tunnel.port | Tunnel port on the client side. For aggregated sessions, this is the client's tunnel port corresponding to the last session in the aggregate. | long |
| zscaler_zia.firewall.tunnel.type | Traffic forwarding method used to send the traffic to the firewall. | keyword |


### tunnel

This is the `tunnel` dataset.

#### Example

An example event for `tunnel` looks as following:

```json
{
    "@timestamp": "2021-12-31T08:08:08.000Z",
    "agent": {
        "ephemeral_id": "a47e8377-379f-491f-be79-efa2e073b3db",
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "zscaler_zia.tunnel",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 0,
        "ip": "0.0.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zia.tunnel",
        "id": "7083020000000007968",
        "ingested": "2023-10-31T04:21:10Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "community_id": "1:y8Yi03w0LBfVdMLE1UG7vvaUt5w=",
        "iana_number": "47",
        "transport": "gre"
    },
    "related": {
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "Unknown"
        ]
    },
    "source": {
        "bytes": 0,
        "ip": "0.0.0.0",
        "port": 0
    },
    "tags": [
        "forwarded",
        "zscaler_zia-tunnel"
    ],
    "user": {
        "name": "Unknown"
    },
    "zscaler_zia": {
        "tunnel": {
            "action": {
                "type": "Tunnel Samples"
            },
            "dpd_packets": "0",
            "location": {
                "name": "Unknown"
            },
            "type": "GRE"
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zia.tunnel.action.type | Type of the record. Possible values [ WL_TUNNEL_IPSECPHASE1, WL_TUNNEL_IPSECPHASE2, WL_TUNNEL_EVENT, WL_TUNNEL_SAMPLES ]. | keyword |
| zscaler_zia.tunnel.authentication.algorithm | Authentication algorithm. | keyword |
| zscaler_zia.tunnel.authentication.type | Authentication type. | keyword |
| zscaler_zia.tunnel.destination.end.ip | Phase 2 policy proposal - Destination IP end. | ip |
| zscaler_zia.tunnel.destination.start.ip | Phase 2 policy proposal - Destination IP start. | ip |
| zscaler_zia.tunnel.destination.start.port | Phase 2 policy proposal - Destination port end. | long |
| zscaler_zia.tunnel.dpd_packets | Number of DPD packets received in 60-second sample window. | keyword |
| zscaler_zia.tunnel.encryption.algorithm | Encryption algorithm. | keyword |
| zscaler_zia.tunnel.ike.version | IKE version (1 or 2). | long |
| zscaler_zia.tunnel.life.bytes | Life bytes (number of traffic to be transacted through tunnel before renegotiation). | long |
| zscaler_zia.tunnel.life.time | Lifetime of IKE Phase 1/2 in seconds. | long |
| zscaler_zia.tunnel.location.name | Location name. | keyword |
| zscaler_zia.tunnel.policy.direction | N/A | keyword |
| zscaler_zia.tunnel.policy.protocol | Phase 2 policy proposal - Protocol. | keyword |
| zscaler_zia.tunnel.protocol | IPSec tunnel protocol type (Zscaler only supports ESP). | keyword |
| zscaler_zia.tunnel.source.end.ip | Phase 2 policy proposal - Source IP end. | ip |
| zscaler_zia.tunnel.source.start.ip | Phase 2 policy proposal - Source IP start. | ip |
| zscaler_zia.tunnel.source.start.port | Phase 2 policy proposal - Source port start. | long |
| zscaler_zia.tunnel.spi | Security Parameter Index. | keyword |
| zscaler_zia.tunnel.spi_in | Initiator cookie. | keyword |
| zscaler_zia.tunnel.spi_out | Responder cookie. | keyword |
| zscaler_zia.tunnel.type | Tunnel type. | keyword |
| zscaler_zia.tunnel.user_ip |  | ip |
| zscaler_zia.tunnel.vendor.name | Vendor name of the edge device. | keyword |


### web

This is the `web` dataset.

#### Example

An example event for `web` looks as following:

```json
{
    "@timestamp": "2021-12-31T08:08:08.000Z",
    "agent": {
        "ephemeral_id": "d0fda0fa-0e77-4307-97ef-719a911d0484",
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "zscaler_zia.web",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "1.128.3.4"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "747b3f2a-8b40-4ee3-9ddd-ec86e51f9342",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "blocked",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "zscaler_zia.web",
        "ingested": "2023-10-31T04:23:26Z",
        "kind": "event",
        "risk_score": 0,
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "testmachine35"
    },
    "http": {
        "request": {
            "bytes": 600,
            "method": "CONNECT",
            "mime_type": "Other",
            "referrer": "None"
        },
        "response": {
            "bytes": 65,
            "status_code": 200
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "http_proxy"
    },
    "related": {
        "hosts": [
            "TestMachine35"
        ],
        "ip": [
            "203.0.113.5",
            "1.128.3.4"
        ],
        "user": [
            "test",
            "administrator1"
        ]
    },
    "rule": {
        "name": "Zscaler Proxy Traffic",
        "ruleset": "FwFilter"
    },
    "source": {
        "nat": {
            "ip": "203.0.113.5"
        },
        "ip": "192.168.1.35"
    },
    "tags": [
        "forwarded",
        "zscaler_zia-web"
    ],
    "url": {
        "domain": "www.example.com",
        "full": "https://www.example.com",
        "original": "https://www.example.com",
        "path": "",
        "scheme": "https"
    },
    "user": {
        "domain": "example.com",
        "email": "test@example.com",
        "name": [
            "test",
            "administrator1"
        ]
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "Windows Microsoft Windows 10 Pro ZTunnel/1.0",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        }
    },
    "zscaler_zia": {
        "web": {
            "app": {
                "class": "General Browsing",
                "name": "General Browsing"
            },
            "ctime": 0,
            "department": "Unknown",
            "device": {
                "hostname": "TestMachine35"
            },
            "dpl": {
                "dictionaries": "None",
                "engine": "None"
            },
            "location": "Test DB",
            "malware": {
                "category": "None"
            },
            "stime": 0,
            "threat": {
                "name": "None"
            },
            "unscannable": {
                "type": "None"
            },
            "url": {
                "category": {
                    "sub": "Web Search",
                    "super": "Information Technology"
                },
                "class": "Business Use"
            }
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zia.web.app.class | The web application class of the application that was accessed. Equivalent to module. | keyword |
| zscaler_zia.web.app.name | Cloud application name. | keyword |
| zscaler_zia.web.bandwidth_throttle | Indicates whether the transaction was throttled due to a configured bandwidth policy. | keyword |
| zscaler_zia.web.ctime | The time from when the first byte of the request hits the ZEN to the time in which the last byte of the response is sent from the ZEN back to the browser. | long |
| zscaler_zia.web.department | Department of the user. | keyword |
| zscaler_zia.web.device.hostname | The obfuscated version of the device owner. This field must be changed manually. | keyword |
| zscaler_zia.web.dpl.dictionaries | The DLP dictionaries that were matched, if any. | keyword |
| zscaler_zia.web.dpl.engine | The DLP engine that was matched, if any. | keyword |
| zscaler_zia.web.encoded_host | Encoded version of the destination host name. | keyword |
| zscaler_zia.web.file.class | Type of file associated with the transaction. | keyword |
| zscaler_zia.web.file.type | Type of file associated with the transaction. | keyword |
| zscaler_zia.web.location | Gateway location or sub-location of the source. | keyword |
| zscaler_zia.web.malware.category | The category of malware that was detected in the transaction, if any. Also indicates if a file was submitted to the Sandbox engine for analysis and the result of the analysis. | keyword |
| zscaler_zia.web.malware.class | The class of malware that was detected in the transaction, if any. | keyword |
| zscaler_zia.web.record.id | N/A | keyword |
| zscaler_zia.web.stime | The round trip time between the ZEN request and the server. | long |
| zscaler_zia.web.threat.name | The name of the threat that was detected in the transaction, if any. | keyword |
| zscaler_zia.web.total.size | Total size, in bytes, of the HTTP transaction; sum of the total request size and total response size. | long |
| zscaler_zia.web.unscannable.type | Unscannable file type. | keyword |
| zscaler_zia.web.upload.file.class |  | keyword |
| zscaler_zia.web.upload.file.name |  | keyword |
| zscaler_zia.web.upload.file.sub_type |  | keyword |
| zscaler_zia.web.upload.file.type |  | keyword |
| zscaler_zia.web.url.category.sub | Category of the destination URL. | keyword |
| zscaler_zia.web.url.category.super | Super category of the destination URL. | keyword |
| zscaler_zia.web.url.class | Class of the destination URL. | keyword |

