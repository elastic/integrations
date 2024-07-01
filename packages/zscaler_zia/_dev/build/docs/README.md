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
            - **SIEM IP Address**: Enter the IP address of the {{ url "fleet-overview" "Elastic agent" }} you’ll be assigning the Zscaler integration to.
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

{{event "alerts"}}

{{fields "alerts"}}

### dns

This is the `dns` dataset.

#### Example

{{event "dns"}}

{{fields "dns"}}

### firewall

This is the `firewall` dataset.

#### Example

{{event "firewall"}}

{{fields "firewall"}}

### tunnel

This is the `tunnel` dataset.

#### Example

{{event "tunnel"}}

{{fields "tunnel"}}

### web

This is the `web` dataset.

#### Example

{{event "web"}}

{{fields "web"}}
