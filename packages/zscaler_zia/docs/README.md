# Zscaler ZIA

This integration is for Zscaler Internet Access logs [ZIA](https://help.zscaler.com/zia/documentation-knowledgebase/authentication-administration). It can be used
to receive logs sent by NSS log server on respective TCP ports, and Sandbox Report using API.

The log message is expected to be in JSON format. The data is mapped to ECS fields where applicable and the remaining fields are written under `zscaler_zia.<data-stream-name>.*`.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This module has been tested against the **Zscaler Internet Access version 6.1** and API version **v1**.


## To collect data from Zscaler ZIA Sandbox Report API, follow the below steps:

1. Go to the Zscaler ZIA Portal and Login by entering an email address and password.
2. Configure OAuth 2.0 for [Okta](https://help.zscaler.com/zia/oauth-2.0-configuration-guide-okta) or [Microsoft Entra ID](https://help.zscaler.com/zia/oauth-2.0-configuration-guide-microsoft-entra-id) for generating OAuth2.0 Credentials.
3. Add [OAuth2.0 Authorization Server](https://help.zscaler.com/zia/managing-oauth-2.0-authorization-servers). 

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
                - **Audit**: 9029
                - **DNS**: 9011
                - **Endpoint DLP**: 9023
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
              - **Audit**: 9562
              - **DNS**: 9556
              - **Endpoint DLP**: 9561
              - **Firewall**: 9557
              - **Tunnel**: 9558
              - **Web**: 9559
          - Select JSON as feed output type.
          - Add same custom header along with its value on both the side for additional security.
          ![Cloud NSS Feeds setup image](../img/cloud_nss_feeds.png?raw=true)
3. Repeat step 2 for each log type.

**Please make sure to use the given response formats for NSS and Cloud NSS Feeds.**

Note: Please make sure to use latest version of given response formats.


## Documentation and configuration

### Alerts

- Default port (NSS Feed): _9010_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/about-alerts)

Zscaler Alerts response format (v1):
```
<%d{syslogid}>%s{Monthname} %2d{Dayofmonth} %02d{Hour}:%02d{Minutes}:%02d{Seconds} [%s{Deviceip}] ZscalerNSS: %s{Eventinfo}\n
```

Sample Response:
```
<114>Dec 10 14:04:28 [175.16.199.1] ZscalerNSS: Zscaler cloud configuration connection to  175.16.199.1:443 lost and unavailable for the past 2325.00 minutes
```
### Audit Log

- Default port (NSS Feed): _9029_
- Default port (Cloud NSS Feed): _9562_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/adding-cloud-nss-feeds-admin-audit-logs)

Zscaler Audit Log response format (v1):
```
\{"sourcetype":"zscalernss-audit","event":\{"time":"%s{time}","recordid":"%d{recordid}","action":"%s{action}","category":"%s{category}","subcategory":"%s{subcategory}","resource":"%s{resource}","interface":"%s{interface}","adminid":"%s{adminid}","clientip":"%s{clientip}","result":"%s{result}","errorcode":"%s{errorcode}","auditlogtype":"%s{auditlogtype}","preaction":%s{preaction},"postaction":%s{postaction}\}\}
```

Sample Response:
```json
{"sourcetype":"zscalernss-audit","event":{"time":"Mon Oct 16 22:55:48 2023","recordid":"1234","action":"Activate","category":"DATA_LOSS_PREVENTION_RESOURCE","subcategory":"DLP_DICTIONARY","resource":"SSL Rule Name","interface":"API","adminid":"example@zscaler.com","clientip":"89.160.20.112","result":"SUCCESS","errorcode":"AUTHENTICATION_FAILED","auditlogtype":"ZIA Portal Audit Log","timezone":"UTC","preaction":{},"postaction":{}}}
```

### DNS Log

- Default port (NSS Feed): _9011_
- Default port (Cloud NSS Feed): _9556_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-dns-logs)

Zscaler DNS Log response format (v2):
```
\{"sourcetype":"zscalernss-dns","event":\{"user":"%s{elogin}","department":"%s{edepartment}","location":"%s{elocation}","clt_sip":"%s{cip}","cloudname":"%s{cloudname}","company":"%s{company}","datacenter":"%s{datacenter}","datacentercity":"%s{datacentercity}","datacentercountry":"%s{datacentercountry}","day_of_month":"%02d{dd}","dept":"%s{dept}","deviceappversion":"%s{deviceappversion}","devicehostname":"%s{devicehostname}","devicemodel":"%s{devicemodel}","devicename":"%s{devicename}","deviceostype":"%s{deviceostype}","deviceosversion":"%s{deviceosversion}","deviceowner":"%s{deviceowner}","devicetype":"%s{devicetype}","dnsapp":"%s{dnsapp}","dnsappcat":"%s{dnsappcat}","dns_gateway_status":"%s{dnsgw_flags}","dns_gateway_rule":"%s{dnsgw_slot}","dns_gateway_server_protocol":"%s{dnsgw_srv_proto}","category":"%s{domcat}","durationms":"%d{durationms}","ecs_prefix":"%s{ecs_prefix}","ecs_slot":"%s{ecs_slot}","epochtime":"%d{epochtime}","error":"%s{error}","hour":"%02d{hh}","http_code":"%s{http_code}","istcp":"%d{istcp}","loc":"%s{location}","login":"%s{login}","minutes":"%02d{mm}","month":"%s{mon}","month_of_year":"%02d{mth}","odevicehostname":"%s{odevicehostname}","odevicename":"%s{odevicename}","odeviceowner":"%s{odeviceowner}","odomcat":"%s{odomcat}","protocol":"%s{protocol}","recordid":"%d{recordid}","dns_req":"%s{req}","reqaction":"%s{reqaction}","reqrulelabel":"%s{reqrulelabel}","dns_reqtype":"%s{reqtype}","dns_resp":"%s{res}","resaction":"%s{resaction}","respipcategory":"%s{respipcat}","resrulelabel":"%s{resrulelabel}","restype":"%s{restype}","srv_dip":"%s{sip}","srv_dport":"%d{sport}","second":"%02d{ss}","datetime":"%s{time}","tz":"%s{tz}","year":"%04d{yyyy}"\}\}
```

Sample Response:
```json
{"sourcetype":"zscalernss-dns","event":{"cloudname":"zscaler.net","datetime":"Mon Oct 16 22:55:48 2023","devicemodel":"VMware7,1","restype":"IPv4","dns_req":"mail.safemarch.com","dns_reqtype":"A record","error":"EMPTY_RESP","durationms":"1000","recordid":"45648954","tz":"GMT","devicename":"admin","devicehostname":"THINKPADSMITH","deviceostype":"Windows OS","deviceosversion":"Microsoft Windows 10 Enterprise;64 bit","devicetype":"Zscaler Client Connector","http_code":"100","dnsapp":"Google DNS","dns_gateway_server_protocol":"TCP","protocol":"TCP","company":"Zscaler","reqrulelabel":"RULE_1","resrulelabel":"RULE_RES","clt_sip":"81.2.69.192","srv_dip":"175.16.199.0","srv_dport":"1025","user":"jdoe1@safemarch.com","datacentercity":"Sa","datacentercountry":"US","datacenter":"CA Client Node DC","day":"Mon","day_of_month":"16","department":"EDept","dept":"Sales","deviceappversion":"4.3.0.18","deviceowner":"jsmith","dnsappcat":"Network Service","dns_gateway_rule":"DNS GATEWAY Rule 1","dns_gateway_status":"PRIMARY_SERVER_RESPONSE_PASS","category":"Professional Services","ecs_prefix":"192.168.0.0","ecs_slot":"ECS Slot #17","eedone":"Yes","epochtime":"1578128400","hour":"22","istcp":"1","loc":"Headquarters","location":"ELocation","login":"jdoe@safemarch.com","minutes":"55","month":"Oct","month_of_year":"10","oclientsourceip":"9960223283","odevicename":"2175092224","odeviceowner":"10831489","odomcat":"4951704103","odevicehostname":"2168890624","reqaction":"REQ_ALLOW","dns_resp":"www.example.com","respipcategory":"Adult Themes","resaction":"RES_Action","respipcat":"Adult Themes","second":"48","year":"2023"}}
```

### Endpoint DLP Log

- Default port (NSS Feed): _9023_
- Default port (Cloud NSS Feed): _9561_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-endpoint-dlp-logs)

Zscaler Endpoint DLP Log response format (v1):
```
\{"sourcetype":"zscalernss-edlp","event":\{"actiontaken":"%s{actiontaken}","activitytype":"%s{activitytype}","additionalinfo":"%s{addinfo}","channel":"%s{channel}","confirmaction":"%s{confirmaction}","confirmjustification":"%s{confirmjust}","datacenter":"%s{datacenter}","datacentercity":"%s{datacentercity}","datacentercountry":"%s{datacentercountry}","day":"%s{day}","dd":"%02d{dd}","department":"%s{department}","deviceappversion":"%s{deviceappversion}","devicehostname":"%s{devicehostname}","devicemodel":"%s{devicemodel}","devicename":"%s{devicename}","deviceostype":"%s{deviceostype}","deviceosversion":"%s{deviceosversion}","deviceowner":"%s{deviceowner}","deviceplatform":"%s{deviceplatform}","devicetype":"%s{devicetype}","dlpdictcount":"%s{dlpcounts}","dlpdictnames":"%s{dlpdictnames}","dlpenginenames":"%s{dlpengnames}","dlpidentifier":"%llu{dlpidentifier}","dsttype":"%s{dsttype}","eventtime":"%s{eventtime}","expectedaction":"%s{expectedaction}","filedoctype":"%s{filedoctype}","filedstpath":"%s{filedstpath}","filemd5":"%s{filemd5}","filesha":"%s{filesha}","filesrcpath":"%s{filesrcpath}","filetypecategory":"%s{filetypecategory}","filetypename":"%s{filetypename}","hh":"%02d{hh}","itemdstname":"%s{itemdstname}","itemname":"%s{itemname}","itemsrcname":"%s{itemsrcname}","itemtype":"%s{itemtype}","logtype":"%s{logtype}","mm":"%02d{mm}","mon":"%s{mon}","mth":"%02d{mth}","numdlpdictids":"%u{numdlpdictids}","numdlpengineids":"%u{numdlpengids}","odepartment":"%s{odepartment}","odevicehostname":"%s{odevicehostname}","odevicename":"%s{odevicename}","odeviceowner":"%s{odeviceowner}","odlpdictnames":"%s{odlpdictnames}","odlpenginenames":"%s{odlpengnames}","ofiledstpath":"%s{ofiledstpath}","ofilesrcpath":"%s{ofilesrcpath}","oitemdstname":"%s{oitemdstname}","oitemname":"%s{oitemname}","oitemsrcname":"%s{oitemsrcname}","ootherrulelabels":"%s{ootherrulelabels}","otherrulelabels":"%s{otherrulelabels}","orulename":"%s{otriggeredrulelabel}","ouser":"%s{ouser}","recordid":"%llu{recordid}","feedtime":"%s{rtime}","scannedbytes":"%llu{scanned_bytes}","scantime":"%llu{scantime}","severity":"%s{severity}","srctype":"%s{srctype}","ss":"%02d{ss}","datetime":"%s{time}","rulename":"%s{triggeredrulelabel}","timezone":"%s{tz}","user":"%s{user}","yyyy":"%04d{yyyy}","zdpmode":"%s{zdpmode}"\}\}
```

Sample Response:
```json
{ "sourcetype": "zscalernss-edlp", "event": { "actiontaken": "allow", "activitytype": "email_sent", "additionalinfo": "File already open by another application", "channel": "Network Drive Transfer", "confirmaction": "confirm", "confirmjustification": "My manager approved it", "datacenter": "Georgia", "datacentercity": "Atlanta", "datacentercountry": "US", "day": "Mon", "dd": "16", "department": "TempDept", "deviceappversion": "Ver-2199", "devicehostname": "Host", "devicemodel": "Model-2022", "devicename": "Dev 1", "deviceostype": "Windows", "deviceosversion": "Win-11", "deviceowner": "Administrator", "deviceplatform": "Windows", "devicetype": "WinUser", "dlpdictcount": "12|13", "dlpdictnames": "dlp: dlp discription|dlp1: dlp discription1|dlp2: dlp discription2", "dlpenginenames": "dlpengine", "dlpidentifier": "12", "dsttype": "personal_cloud_storage", "eventtime": "Mon Oct 16 22:55:48 2023", "expectedaction": "block", "filedoctype": "Medical", "filedstpath": "dest_path", "filemd5": "938c2cc0dcc05f2b68c4287040cfcf71", "filesha": "076085239f3a10b8f387c4e5d4261abf8d109aa641be35a8d4ed2d775eb09612", "filesrcpath": "source_path", "filetypecategory": "PLS File (pls)", "filetypename": "exe64", "hh": "22", "itemdstname": "nanolog", "itemname": "endpoint_dlp", "itemsrcname": "endpoint", "itemtype": "email_attachment", "logtype": "dlp_incident", "mm": "55", "mon": "Oct", "mth": "10", "numdlpdictids": "8", "numdlpengineids": "12", "recordid": "2", "feedtime": "Mon Oct 16 22:55:48 2023", "scannedbytes": "290812", "scantime": "1210", "severity": "High Severity", "srctype": "network_share", "ss": "48", "datetime": "Mon Oct 16 22:55:48 2023", "rulename": "configured_rule", "timezone": "GMT", "user": "TempUser", "yyyy": "2023", "zdpmode": "block mode", "odepartment": "4094304256", "odevicehostname": "4094304255", "odevicename": "4094304251", "odeviceowner": "4094304226", "odlpdictnames": "4094304456", "odlpenginenames": "4094364256", "ofiledstpath": "4094304296", "ofilesrcpath": "4094304206", "oitemdstname": "409430476", "oitemname": "40943042567", "oitemsrcname": "4094305256", "ootherrulelabels": "4036304256", "orulename": "40943049956", "ouser": "40943042569", "otherrulelabels": "9094304256" } }
```

### Firewall Log

- Default port (NSS Feed): _9012_
- Default port (Cloud NSS Feed): _9557_

See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-firewall-logs)

Zscaler Firewall Log response format (v2):
```
\{"sourcetype":"zscalernss-fw","event":\{"datetime":"%s{time}","outbytes":"%ld{outbytes}","cltdomain":"%s{cdfqdn}","destcountry":"%s{destcountry}","cdip":"%s{cdip}","sdip":"%s{sdip}","cdport":"%d{cdport}","sdport":"%d{sdport}","devicemodel":"%s{devicemodel}","action":"%s{action}","duration":"%d{duration}","recordid":"%d{recordid}","tz":"%s{tz}","devicename":"%s{devicename}","devicehostname":"%s{devicehostname}","deviceostype":"%s{deviceostype}","deviceosversion":"%s{deviceosversion}","nwapp":"%s{nwapp}","nwsvc":"%s{nwsvc}","proto":"%s{ipproto}","ipsrulelabel":"%s{ipsrulelabel}","dnatrulelabel":"%s{dnatrulelabel}","rdr_rulename":"%s{rdr_rulename}","rule":"%s{rulelabel}","rulelabel":"%s{erulelabel}","inbytes":"%ld{inbytes}","srcipcountry":"%s{srcip_country}","csip":"%s{csip}","ssip":"%s{ssip}","csport":"%d{csport}","ssport":"%d{ssport}","user":"%s{elogin}","aggregate":"%s{aggregate}","bypassed_session":"%d{bypassed_session}","bypass_time":"%s{bypass_etime}","datacentercity":"%s{datacentercity}","datacentercountry":"%s{datacentercountry}","datacenter":"%s{datacenter}","day_of_month":"%02d{dd}","department":"%s{edepartment}","dept":"%s{dept}","deviceappversion":"%s{deviceappversion}","deviceowner":"%s{deviceowner}","avgduration":"%d{avgduration}","durationms":"%d{durationms}","epochtime":"%d{epochtime}","external_deviceid":"%s{external_deviceid}","flow_type":"%s{flow_type}","forward_gateway_name":"%s{fwd_gw_name}","hour":"%02d{hh}","ipcat":"%s{ipcat}","ips_custom_signature":"%d{ips_custom_signature}","location":"%s{location}","locationname":"%s{elocation}","login":"%s{login}","minute":"%02d{mm}","month":"%s{mon}","month_of_year":"%02d{mth}","dnat":"%s{dnat}","odevicename":"%s{odevicename}","odeviceowner":"%s{odeviceowner}","ofwd_gw_name":"%s{ofwd_gw_name}","odevicehostname":"%s{odevicehostname}","oipcat":"%s{oipcat}","oipsrulelabel":"%s{oipsrulelabel}","ordr_rulename":"%s{ordr_rulename}","orulelabel":"%s{orulelabel}","ozpa_app_seg_name":"%s{ozpa_app_seg_name}","second":"%02d{ss}","numsessions":"%d{numsessions}","stateful":"%s{stateful}","threat_name":"%s{threatname}","threatcat":"%s{threatcat}","threatname":"%s{ethreatname}","tsip":"%s{tsip}","tuntype":"%s{ttype}","year":"%04d{yyyy}","ztunnelversion":"%s{ztunnelversion}","zpa_app_seg_name":"%s{zpa_app_seg_name}"\}\}
```

Sample Response:
```json
{"sourcetype":"zscalernss-fw","event":{"datetime":"Mon Oct 16 22:55:48 2023","cltdomain":"www.example.com","cdip":"2a02:cf40::","outbytes":"10000","cdport":"22","destcountry":"USA","devicemodel":"20L8S7WC08","sdip":"67.43.156.0","duration":"600","sdport":"443","tz":"GMT","action":"Blocked","devicehostname":"THINKPADSMITH","recordid":"123456","deviceosversion":"Version 10.14.2 (Build 18C54)","devicename":"admin","nwsvc":"HTTP","deviceostype":"iOS","ipsrulelabel":"Default IPS Rule","nwapp":"Skype","rdr_rulename":"FWD_Rule_1","proto":"TCP","rulelabel":"rule1","dnatrulelabel":"DNAT_Rule_1","srcipcountry":"United States","rule":"Default_Firewall_Filtering_Rule","ssip":"1.128.0.0","inbytes":"10000","ssport":"22","csip":"0.0.0.0","aggregate":"Yes","csport":"25","bypass_time":"Mon Oct 16 22:55:48 2023","user":"jdoe%40safemarch.com","datacentercountry":"US","bypassed_session":"1","day":"Mon","datacentercity":"Sa","department":"sales","datacenter":"CA Client Node DC","deviceappversion":"2.0.0.120","day_of_month":"16","avgduration":"600","dept":"Sales","eedone":"Yes","deviceowner":"jsmith","external_deviceid":"1234","durationms":"600","forward_gateway_name":"FWD_1","epochtime":"1578128400","ipcat":"Finance","flow_type":"Direct","location":"Headquarters","hour":"22","login":"jdo%40safemarch.com","ips_custom_signature":"0","month":"Oct","locationname":"Headquarters","dnat":"Yes","minute":"55","odevicename":"2175092224","month_of_year":"10","ofwd_gw_name":"8794487099","ocsip":"9960223283","oipcat":"5300295980","odeviceowner":"10831489","odnatlabel":"7956407282","odevicehostname":"2168890624","orulelabel":"624054738","oipsrulelabel":"6200694987","second":"48","ordr_rulename":"3399565100","stateful":"Yes","ozpa_app_seg_name":"7648246731","threatcat":"Botnet Callback","numsessions":"5","tsip":"89.160.20.128","threat_name":"Linux.Backdoor.Tsunami","year":"2023","threatname":"Linux.Backdoor","zpa_app_seg_name":"ZPA_test_app_segment","tuntype":"L2 tunnel","ztunnelversion":"ZTUNNEL_1_0"}}
```

### Tunnel Log

- Default port (NSS Feed): _9013_
- Default port (Cloud NSS Feed): _9558_

See: [Zscaler Vendor documentation]( https://help.zscaler.com/zia/nss-feed-output-format-tunnel-logs)

Zscaler Tunnel Log response formats (v2):
- Tunnel Event:
    ```
    \{"sourcetype":"zscalernss-tunnel","event":\{"datetime":"%s{datetime}","day":"%s{day}","dd":"%02d{dd}","destinationip":"%s{destvip}","event":"%s{event}","eventreason":"%s{eventreason}","hh":"%02d{hh}","locationname":"%s{locationname}","mm":"%02d{mm}","mon":"%s{mon}","mth":"%02d{mth}","olocationname":"%s{olocationname}","ovpncredentialname":"%s{ovpncredentialname}","recordid":"%d{recordid}","sourceip":"%s{sourceip}","sourceport":"%d{srcport}","ss":"%02d{ss}","Recordtype":"%s{tunnelactionname}","tunneltype":"%s{tunneltype}","timezone":"%s{tz}","user":"%s{vpncredentialname}","yyyy":"%04d{yyyy}"\}\}
    ```
- Sample Event:
    ```
    \{"sourcetype":"zscalernss-tunnel","event":\{"datetime":"%s{datetime}","day":"%s{day}","dd":"%02d{dd}","destinationip":"%s{destvip}","dpdrec":"%d{dpdrec}","hh":"%02d{hh}","locationname":"%s{locationname}","mm":"%02d{mm}","mon":"%s{mon}","mth":"%02d{mth}","olocationname":"%s{olocationname}","ovpncredentialname":"%s{ovpncredentialname}","recordid":"%d{recordid}","rxbytes":"%lu{rxbytes}","rxpackets":"%d{rxpackets}","sourceip":"%s{sourceip}","sourceport":"%d{srcport}","ss":"%02d{ss}","Recordtype":"%s{tunnelactionname}","tunneltype":"%s{tunneltype}","txbytes":"%lu{txbytes}","txpackets":"%d{txpackets}","timezone":"%s{tz}","user":"%s{vpncredentialname}","yyyy":"%04d{yyyy}"\}\}
    ```
- IKE Phase 1
    ```
    \{"sourcetype":"zscalernss-tunnel","event":\{"algo":"%s{algo}","authentication":"%s{authentication}","authtype":"%s{authtype}","datetime":"%s{datetime}","day":"%s{day}","dd":"%02d{dd}","destinationip":"%s{destvip}","destinationport":"%d{dstport}","hh":"%02d{hh}","ikeversion":"%d{ikeversion}","lifetime":"%d{lifetime}","locationname":"%s{locationname}","mm":"%02d{mm}","mon":"%s{mon}","mth":"%02d{mth}","olocationname":"%s{olocationname}","ovpncredentialname":"%s{ovpncredentialname}","recordid":"%d{recordid}","sourceip":"%s{sourceip}","spi_in":"%lu{spi_in}","spi_out":"%lu{spi_out}","sourceport":"%d{srcport}","ss":"%02d{ss}","Recordtype":"%s{tunnelactionname}","tunneltype":"IPSEC IKEV %d{ikeversion}","timezone":"%s{tz}","vendorname":"%s{vendorname}","user":"%s{vpncredentialname}","yyyy":"%04d{yyyy}"\}\}
    ```
- IKE Phase 2
    ```
    \{"sourcetype":"zscalernss-tunnel","event":\{"algo":"%s{algo}","authentication":"%s{authentication}","authtype":"%s{authtype}","datetime":"%s{datetime}","day":"%s{day}","dd":"%02d{dd}","destinationipend":"%s{destipend}","destinationipstart":"%s{destipstart}","destinationportstart":"%d{destportstart}","destinationip":"%s{destvip}","hh":"%02d{hh}","ikeversion":"%d{ikeversion}","lifebytes":"%d{lifebytes}","lifetime":"%d{lifetime}","locationname":"%s{locationname}","mm":"%02d{mm}","mon":"%s{mon}","mth":"%02d{mth}","olocationname":"%s{olocationname}","ovpncredentialname":"%s{ovpncredentialname}","protocol":"%s{protocol}","recordid":"%d{recordid}","sourceip":"%s{sourceip}","spi":"%d{spi}","srcipend":"%s{srcipend}","srcipstart":"%s{srcipstart}","sourceportstart":"%d{srcportstart}","ss":"%02d{ss}","Recordtype":"%s{tunnelactionname}","tunnelprotocol":"%s{tunnelprotocol}","tunneltype":"IPSEC IKEV %d{ikeversion}","timezone":"%s{tz}","user":"%s{vpncredentialname}","yyyy":"%04d{yyyy}"\}\}
    ```

Sample Response:
```json
{"sourcetype":"zscalernss-tunnel","event":{"datetime":"Mon Oct 16 22:55:48 2023","destinationip":"67.43.156.1","destinationport":"500","recordid":"111234","timezone":"GMT","sourceip":"67.43.156.0","sourceport":"500","user":"jdoe@safemarch.com","authentication":"HMAC_MD5","authtype":"PSKEY","day":"Mon","dd":"16","algo":"DES_CBC","hh":"22","ikeversion":"IKE_VERSION_2","lifetime":"86400","locationname":"Headquarters","mm":"55","mon":"Oct","mth":"10","olocationname":"2168890624","ovpncredentialname":"4094304256","ss":"48","spi_in":"None","spi_out":"None","Recordtype":"None","vendorname":"CISCO","yyyy":"2023"}}
```

### Web Log

- Default port (NSS Feed): _9014_
- Default port (Cloud NSS Feed): _9559_
- Add characters **"** and **\\** in **feed escape character** while configuring Web Log.

![Escape feed setup image](../img/escape_feed.png?raw=true)
See: [Zscaler Vendor documentation](https://help.zscaler.com/zia/nss-feed-output-format-web-logs)

Zscaler Web Log response format (v6):
```
\{"sourcetype":"zscalernss-web","event":\{"time":"%s{time}","cloudname":"%s{cloudname}","host":"%s{ehost}","serverip":"%s{sip}","external_devid":"%s{external_devid}","devicemodel":"%s{devicemodel}","action":"%s{action}","recordid":"%d{recordid}","reason":"%s{reason}","threatseverity":"%s{threatseverity}","tz":"%s{tz}","filesubtype":"%s{filesubtype}","upload_filesubtype":"%s{upload_filesubtype}","sha256":"%s{sha256}","bamd5":"%s{bamd5}","filename":"%s{efilename}","upload_filename":"%s{eupload_filename}","filetype":"%s{filetype}","devicename":"%s{edevicename}","devicehostname":"%s{devicehostname}","deviceostype":"%s{deviceostype}","deviceosversion":"%s{deviceosversion}","devicetype":"%s{devicetype}","reqsize":"%d{reqsize}","reqmethod":"%s{reqmethod}","refererurl":"%s{ereferer}","refererpath":"%s{erefererpath}","respsize":"%d{respsize}","respcode":"%s{respcode}","reqversion":"%s{reqversion}","respversion":"%s{respversion}","proto":"%s{proto}","company":"%s{company}","dlpmd5":"%s{dlpmd5}","apprulelabel":"%s{eapprulelabel}","dlprulename":"%s{dlprulename}","rulelabel":"%s{erulelabel}","urlfilterrulelabel":"%s{eurlfilterrulelabel}","cltip":"%s{cip}","cltintip":"%s{cintip}","cltsourceport":"%d{clt_sport}","threatname":"%s{threatname}","cltsslcipher":"%s{clientsslcipher}","clttlsversion":"%s{clienttlsversion}","eurl":"%s{eurl}","urlpath":"%s{eurlpath}","useragent":"%s{eua}","login":"%s{elogin}","applayerprotocol":"%s{alpnprotocol}","appclass":"%s{appclass}","appname":"%s{appname}","appriskscore":"%s{app_risk_score}","bandwidthclassname":"%s{bwclassname}","bandwidthrulename":"%s{bwrulename}","bwthrottle":"%s{bwthrottle}","bypassedtime":"%s{bypassed_etime}","bypassedtraffic":"%d{bypassed_traffic}","cltsslsessreuse":"%s{clientsslsessreuse}","cltpubip":"%s{cpubip}","cltsslfailcount":"%d{cltsslfailcount}","cltsslfailreason":"%s{cltsslfailreason}","contenttype":"%s{contenttype}","datacentercity":"%s{datacentercity}","datacentercountry":"%s{datacentercountry}","datacenter":"%s{datacenter}","day":"%s{day}","day_of_month":"%02d{dd}","dept":"%s{dept}","deviceappversion":"%s{deviceappversion}","deviceowner":"%s{deviceowner}","df_hosthead":"%s{df_hosthead}","df_hostname":"%s{df_hostname}","dlpdicthitcount":"%s{dlpdicthitcount}","dlpdict":"%s{dlpdict}","dlpeng":"%s{dlpeng}","dlpidentifier":"%d{dlpidentifier}","eedone":"%s{eedone}","epochtime":"%d{epochtime}","fileclass":"%s{fileclass}","flow_type":"%s{flow_type}","forward_gateway_ip":"%s{fwd_gw_ip}","forward_gateway_name":"%s{fwd_gw_name}","forward_type":"%s{fwd_type}","hour":"%02d{hh}","is_sslexpiredca":"%s{is_sslexpiredca}","is_sslselfsigned":"%s{is_sslselfsigned}","is_ssluntrustedca":"%s{is_ssluntrustedca}","keyprotectiontype":"%s{keyprotectiontype}","location":"%s{elocation}","department":"%s{edepartment}","malwarecategory":"%s{malwarecat}","malwareclass":"%s{malwareclass}","minute":"%02d{mm}","mobappcategory":"%s{mobappcat}","mobappname":"%s{emobappname}","mobdevtype":"%s{mobdevtype}","module":"%s{module}","month":"%s{mon}","month_of_year":"%02d{mth}","nssserviceip":"%s{nsssvcip}","oapprulelabel":"%s{oapprulelabel}","obwclassname":"%s{obwclassname}","ocip":"%d{ocip}","ocpubip":"%d{ocpubip}","odevicehostname":"%s{odevicehostname}","odevicename":"%s{odevicename}","odeviceowner":"%s{odeviceowner}","odlpdict":"%s{odlpdict}","odlpeng":"%s{odlpeng}","odlprulename":"%s{odlprulename}","ofwd_gw_name":"%s{ofwd_gw_name}","ologin":"%s{ologin}","ordr_rulename":"%s{ordr_rulename}","ourlcat":"%s{ourlcat}","ourlfilterrulelabel":"%s{ourlfilterrulelabel}","ozpa_app_seg_name":"%s{ozpa_app_seg_name}","externalsslpolicyreason":"%s{externalspr}","productversion":"%s{productversion}","rdr_rulename":"%s{rdr_rulename}","refererhost":"%s{erefererhost}","reqheadersize":"%d{reqhdrsize}","reqdatasize":"%d{reqdatasize}","respheadersize":"%d{resphdrsize}","respdatasize":"%d{respdatasize}","riskscore":"%d{riskscore}","ruletype":"%s{ruletype}","second":"%02d{ss}","srvcertchainvalpass":"%s{srvcertchainvalpass}","srvcertvalidationtype":"%s{srvcertvalidationtype}","srvcertvalidityperiod":"%s{srvcertvalidityperiod}","srvsslcipher":"%s{srvsslcipher}","serversslsessreuse":"%s{serversslsessreuse}","srvocspresult":"%s{srvocspresult}","srvtlsversion":"%s{srvtlsversion}","srvwildcardcert":"%s{srvwildcardcert}","ssldecrypted":"%s{ssldecrypted}","throttlereqsize":"%d{throttlereqsize}","throttlerespsize":"%d{throttlerespsize}","totalsize":"%d{totalsize}","trafficredirectmethod":"%s{trafficredirectmethod}","unscannabletype":"%s{unscannabletype}","upload_doctypename":"%s{upload_doctypename}","upload_fileclass":"%s{upload_fileclass}","upload_filetype":"%s{upload_filetype}","urlcatmethod":"%s{urlcatmethod}","urlsubcat":"%s{urlcat}","urlsupercat":"%s{urlsupercat}","urlclass":"%s{urlclass}","useragentclass":"%s{uaclass}","useragenttoken":"%s{ua_token}","userlocationname":"%s{euserlocationname}","year":"%04d{yyyy}","ztunnelversion":"%s{ztunnelversion}","zpa_app_seg_name":"%s{zpa_app_seg_name}"\}\}
```

Sample Response:
```json
{"sourcetype":"zscalernss-web","event":{"time":"Mon Oct 16 22:55:48 2023","cloudname":"zscaler.net","host":"mail.google.com","serverip":"1.128.0.0","external_devid":"1234","devicemodel":"20L8S7WC08","action":"Allowed","recordid":123456789,"reason":"File Attachment Cautioned","threatseverity":"Critical (90–100)","tz":"GMT","filesubtype":"exe","upload_filesubtype":"rar","sha256":"81ec78bc8298568bb5ea66d3c2972b670d0f7459b6cdbbcaacce90ab417ab15c","bamd5":"196a3d797bfee07fe4596b69f4ce1141","filename":"nssfeed.txt","upload_filename":"nssfeed.exe","filetype":"RAR Files","devicename":"PC11NLPA%3A5F08D97BBF43257A8FB4BBF4061A38AE324EF734","devicehostname":"THINKPADSMITH","deviceostype":"iOS","deviceosversion":"Version 10.14.2 (Build 18C54)","devicetype":"Zscaler Client Connector","reqsize":1300,"reqmethod":"invalid","refererurl":"www.example.com","refererpath":"/search?filters=guid%3A%2240-en-dia%22+lang%3A%22en%22&form=S00&q=how+to+use+remote+desktop+to+connect+to+a+windows+10+pc","respsize":10500,"respcode":"100","reqversion":"1.1","respversion":"1","proto":"HTTP","company":"Zscaler","dlpmd5":"154f149b1443fbfa8c121d13e5c019a1","apprulelabel":"File_Sharing_1","dlprulename":"DLP_Rule_1","rulelabel":"URL_Filtering_1","urlfilterrulelabel":"URL_Filtering_2","cltip":"81.2.69.144","cltintip":"89.160.20.128","cltsourceport":12345,"threatname":"EICAR Test File","cltsslcipher":"SSL3_CK_RSA_NULL_MD5","clttlsversion":"SSL2","eurl":"www.trythisencodeurl.com/index","urlpath":"/params?Id=1&ts=2006-01-02T15%3A04%3A05Z07%3A00&user=65792&version=10.0.19041.1266","useragent":"Mozilla/5.0","login":"jdoe@safemarch.com","applayerprotocol":"FTP","appclass":"Administration","appname":"Adobe Connect","appriskscore":"1","bandwidthclassname":"Entertainment","bandwidthrulename":"Office 365","bwthrottle":"Yes","bypassedtime":"Mon Oct 16 22:55:48 2023","bypassedtraffic":"1","cltsslsessreuse":"Unknown","cltpubip":"175.16.199.0","cltsslfailcount":100,"cltsslfailreason":"Bad Record Mac","contenttype":"application/vnd_apple_keynote","datacentercity":"Sa","datacentercountry":"US","datacenter":"CA Client Node DC","day":"Mon","day_of_month":16,"dept":"Sales","deviceappversion":"1.128.0.0","deviceowner":"jsmith","df_hosthead":"df_hosthead","df_hostname":"df_hostname","dlpdicthitcount":"4","dlpdict":"Credit Cards","dlpeng":"HIPAA","dlpidentifier":6646484838839026000,"eedone":"Yes","epochtime":1578128400,"fileclass":"Active Web Contents","flow_type":"Direct","forward_gateway_ip":"10.1.1.1","forward_gateway_name":"FWD_1","forward_type":"Direct","hour":22,"is_sslexpiredca":"Yes","is_sslselfsigned":"Yes","is_ssluntrustedca":"Pass","keyprotectiontype":"HSM Protection","location":"Headquarters","department":"Department%5CrN%40me","malwarecategory":"Adware","malwareclass":"Sandbox","minute":55,"mobappcategory":"Communication","mobappname":"Amazon","mobdevtype":"Google Android","module":"Administration","month":"Oct","month_of_year":10,"nssserviceip":"192.168.2.200","oapprulelabel":"5300295980","obwclassname":"10831489","ocip":6200694987,"ocpubip":624054738,"odevicehostname":"2168890624","odevicename":"2175092224","odeviceowner":"10831489","odlpdict":"10831489","odlpeng":"4094304256","odlprulename":"6857275752","ofwd_gw_name":"8794487099","ologin":"4094304256","ordr_rulename":"3399565100","ourlcat":"7956407282","ourlfilterrulelabel":"4951704103","ozpa_app_seg_name":"7648246731","externalsslpolicyreason":"Blocked","productversion":"5.0.902.95524_04","rdr_rulename":"FWD_Rule_1","refererhost":"www.example.com for http://www.example.com/index.html","reqheadersize":300,"reqdatasize":1000,"respheadersize":500,"respdatasize":10000,"riskscore":10,"ruletype":"File Type Control","second":48,"srvcertchainvalpass":"Unknown","srvcertvalidationtype":"EV (Extended Validation)","srvcertvalidityperiod":"Short","srvsslcipher":"SSL3_CK_RSA_NULL_MD5","serversslsessreuse":"Unknown","srvocspresult":"Good","srvtlsversion":"SSL2","srvwildcardcert":"Unknown","ssldecrypted":"Yes","throttlereqsize":5,"throttlerespsize":7,"totalsize":11800,"trafficredirectmethod":"DNAT (Destination Translation)","unscannabletype":"Encrypted File","upload_doctypename":"Corporate Finance","upload_fileclass":"upload_fileclass","upload_filetype":"RAR Files","urlcatmethod":"Database A","urlsubcat":"Entertainment","urlsupercat":"Travel","urlclass":"Bandwidth Loss","useragentclass":"Firefox","useragenttoken":"Google Chrome (0.x)","userlocationname":"userlocationname","year":2023,"ztunnelversion":"ZTUNNEL_1_0","zpa_app_seg_name":"ZPA_test_app_segment"}}
```
### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Zscaler ZIA.
3. Click on the "Zscaler ZIA" integration from the search results.
4. Click on the "Add Zscaler ZIA" button to add the integration.
5. Configure all required integration parameters, including URL, Client ID, Client Secret, Scope, Token URL, Details and MD5, to enable data collection for Zscaler ZIA API. For TCP and HTTP Endpoint data collection, provide parameters such as listen address and listen port.
6. Save the integration.

Caveats:

- To ensure that URLs are processed correctly, logs which have a `network.protocol` value that is not `http` or `https` will be implicitly converted to `https` for the purposes of URL parsing. The original value of `network.protocol` will be preserved.

## Logs reference

### alerts

This is the `alerts` dataset.

#### Example

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2024-12-10T13:40:32.000Z",
    "agent": {
        "ephemeral_id": "9c123331-181f-42a0-af82-70e49ce7aaa1",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
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
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "zscaler_zia.alerts",
        "ingested": "2024-07-04T11:58:59Z"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.243.6:40328"
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
| zscaler_zia.alerts.destination.address |  | keyword |
| zscaler_zia.alerts.destination.ip |  | ip |
| zscaler_zia.alerts.destination.port |  | long |
| zscaler_zia.alerts.log_feed_name | Name of the NSS log feed. | keyword |
| zscaler_zia.alerts.log_syslog_priority |  | long |
| zscaler_zia.alerts.message |  | keyword |
| zscaler_zia.alerts.timestamp |  | date |


### audit

This is the `audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2023-10-16T22:55:48.000Z",
    "agent": {
        "ephemeral_id": "8fbed883-d7e9-41ab-99d8-6fef7131d443",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zia.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "error": {
        "code": "AUTHENTICATION_FAILED"
    },
    "event": {
        "action": "activate",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "zscaler_zia.audit",
        "id": "1234",
        "ingested": "2024-07-04T12:01:12Z",
        "kind": "event",
        "outcome": "success",
        "timezone": "UTC",
        "type": [
            "change"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "ip": [
            "89.160.20.112"
        ],
        "user": [
            "example",
            "example@zscaler.com"
        ]
    },
    "rule": {
        "category": "DLP_DICTIONARY",
        "name": "SSL Rule Name",
        "ruleset": "DATA_LOSS_PREVENTION_RESOURCE"
    },
    "source": {
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112"
    },
    "tags": [
        "forwarded",
        "zscaler_zia-audit"
    ],
    "user": {
        "domain": "zscaler.com",
        "email": "example@zscaler.com",
        "name": "example"
    },
    "zscaler_zia": {
        "audit": {
            "audit_log_type": "ZIA Portal Audit Log",
            "interface": "API",
            "result": "SUCCESS"
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
| zscaler_zia.audit.action | The action performed by the admin in the ZIA Admin Portal. | keyword |
| zscaler_zia.audit.admin_id | The admin's login ID. | keyword |
| zscaler_zia.audit.audit_log_type | The Admin Audit log type. | keyword |
| zscaler_zia.audit.category | The location in the ZIA Admin Portal where the action was performed. | keyword |
| zscaler_zia.audit.client_ip | The source IP address for the admin. | ip |
| zscaler_zia.audit.error_code | An optional field that exists only if the result is a failure. | keyword |
| zscaler_zia.audit.interface | The means by which the user performs their actions. | keyword |
| zscaler_zia.audit.post_action | Data after any policy or configuration changes. | flattened |
| zscaler_zia.audit.pre_action | Data before any policy or configuration changes. | flattened |
| zscaler_zia.audit.record.id | The unique record identifier for each log. | keyword |
| zscaler_zia.audit.resource | The specific location within a sub-category. | keyword |
| zscaler_zia.audit.result | The outcome of an action. | keyword |
| zscaler_zia.audit.sub_category | The sub-location in the ZIA Admin Portal where the action was performed. | keyword |
| zscaler_zia.audit.time | The time and date of the transaction. | date |
| zscaler_zia.audit.timezone | The time zone. | keyword |


### dns

This is the `dns` dataset.

#### Example

An example event for `dns` looks as following:

```json
{
    "@timestamp": "2021-12-17T07:27:54.000Z",
    "agent": {
        "ephemeral_id": "6dac0cbb-768a-4dc4-a476-6bf881ed6755",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zia.dns",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "dns": {
        "answers": [
            {
                "data": "Some response string"
            }
        ],
        "question": {
            "name": "example.com",
            "type": "Some type"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zia.dns",
        "duration": 123456000000,
        "ingested": "2024-07-04T12:03:18Z",
        "kind": "event",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "machine9000"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.243.6:52614"
        }
    },
    "network": {
        "protocol": "dns"
    },
    "related": {
        "hosts": [
            "machine9000"
        ],
        "ip": [
            "89.160.20.112",
            "89.160.20.156"
        ],
        "user": [
            "Owner77",
            "some_user",
            "some_user@example.com"
        ]
    },
    "rule": {
        "name": [
            "Access Blocked"
        ]
    },
    "source": {
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112",
        "port": 8080
    },
    "tags": [
        "forwarded",
        "zscaler_zia-dns"
    ],
    "user": {
        "domain": "example.com",
        "email": "some_user@example.com",
        "name": "some_user"
    },
    "zscaler_zia": {
        "dns": {
            "department": "Unknown",
            "device": {
                "owner": "Owner77"
            },
            "dom": {
                "category": "Professional Services"
            },
            "location": "TestLoc DB",
            "request": {
                "action": "REQ_ALLOW"
            },
            "response": {
                "action": "Some Response Action"
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
| zscaler_zia.dns.client.ip | The IP address of the user. | ip |
| zscaler_zia.dns.cloud.name | The Zscaler cloud name. | keyword |
| zscaler_zia.dns.company | The company name. | keyword |
| zscaler_zia.dns.datacenter.city | The city where the data center is located. | keyword |
| zscaler_zia.dns.datacenter.country | The country where the data center is located. | keyword |
| zscaler_zia.dns.datacenter.name | The name of the data center. | keyword |
| zscaler_zia.dns.day | The day of the week. | keyword |
| zscaler_zia.dns.day_of_month | The day of the month. | long |
| zscaler_zia.dns.department |  | keyword |
| zscaler_zia.dns.dept | The department. | keyword |
| zscaler_zia.dns.device.appversion | The app version that the device uses. | keyword |
| zscaler_zia.dns.device.hostname | The host name of the device. | keyword |
| zscaler_zia.dns.device.model | The model of the device. | keyword |
| zscaler_zia.dns.device.name | The name of the device. | keyword |
| zscaler_zia.dns.device.os.type | The OS type of the device. | keyword |
| zscaler_zia.dns.device.os.version | The OS version that the device uses. | keyword |
| zscaler_zia.dns.device.owner | The owner of the device. | keyword |
| zscaler_zia.dns.device.type | The type of device. | keyword |
| zscaler_zia.dns.dns.category | The DNS tunnel or network application category. | keyword |
| zscaler_zia.dns.dns.gateway.rule | The name of the DNS Gateway rule. | keyword |
| zscaler_zia.dns.dns.gateway.server_protocol | The DNS Gateway server protocol. | keyword |
| zscaler_zia.dns.dns.gateway.status | Flags indicating the DNS Gateway status for the transaction. | keyword |
| zscaler_zia.dns.dns.type | The type of DNS tunnel or network application. | keyword |
| zscaler_zia.dns.dom.category | The URL Category of the FQDN in the DNS request. | keyword |
| zscaler_zia.dns.duration.milliseconds | The duration of the DNS request in milliseconds. | long |
| zscaler_zia.dns.ecs.prefix | The EDNS Client Subnet (ECS) prefix used in the DNS request. | keyword |
| zscaler_zia.dns.ecs.slot | The name of the EDNS Client Subnet (ECS) rule that was applied to the DNS transaction. | keyword |
| zscaler_zia.dns.eedone | Indicates if the characters specified in the Feed Escape Character field of the NSS configuration page were hex encoded. | keyword |
| zscaler_zia.dns.epochtime | The epoch time of the transaction. | date |
| zscaler_zia.dns.error | The DNS error code. | keyword |
| zscaler_zia.dns.hour | Hours. | long |
| zscaler_zia.dns.http_code | The HTTP return code. | keyword |
| zscaler_zia.dns.istcp | Indicates if the DNS transaction uses TCP. | keyword |
| zscaler_zia.dns.loc | The gateway location or sub-location of the source. | keyword |
| zscaler_zia.dns.location |  | keyword |
| zscaler_zia.dns.login | The login name in email address format. | keyword |
| zscaler_zia.dns.minutes | Minutes. | long |
| zscaler_zia.dns.month | The name of the month. | keyword |
| zscaler_zia.dns.month_of_year | The month of the year. | long |
| zscaler_zia.dns.obfuscated.client_source_ip | The obfuscated version of the client source IP address. | keyword |
| zscaler_zia.dns.obfuscated.device.name | The obfuscated version of the name of the device. | keyword |
| zscaler_zia.dns.obfuscated.device.owner | The obfuscated version of the owner of the device. | keyword |
| zscaler_zia.dns.obfuscated.dom.category | The obfuscated version of the FQDN in the DNS request. | keyword |
| zscaler_zia.dns.obfuscated.host_name | The obfuscated version of the host name of the device. | keyword |
| zscaler_zia.dns.protocol | The protocol type. | keyword |
| zscaler_zia.dns.record.id | The unique record identifier for each log. | keyword |
| zscaler_zia.dns.request.action | The name of the action that was applied to the DNS request. | keyword |
| zscaler_zia.dns.request.name | The Fully Qualified Domain Name (FQDN) in the DNS request. | keyword |
| zscaler_zia.dns.request.rule.label | The name of the rule that was applied to the DNS request. | keyword |
| zscaler_zia.dns.request.type | The DNS request type. | keyword |
| zscaler_zia.dns.response.action | The name of the action that was applied to the DNS response. | keyword |
| zscaler_zia.dns.response.category | The URL Category of the FQDN in the DNS response. | keyword |
| zscaler_zia.dns.response.ip | The resolved IP in the DNS response. | ip |
| zscaler_zia.dns.response.name | The NAME in the DNS response. | keyword |
| zscaler_zia.dns.response.rule.label | The name of the rule that was applied to the DNS response. | keyword |
| zscaler_zia.dns.response.type | The DNS response type. | keyword |
| zscaler_zia.dns.second | Seconds. | long |
| zscaler_zia.dns.server.ip | The server IP address of the request. | ip |
| zscaler_zia.dns.server.port | The server port of the request. | long |
| zscaler_zia.dns.time | The time and date of the transaction. | date |
| zscaler_zia.dns.timezone | The time zone. This is the same as the time zone you specified when you configured the NSS feed. | keyword |
| zscaler_zia.dns.user |  | keyword |
| zscaler_zia.dns.year | Year. | long |


### endpoint_dlp

This is the `endpoint_dlp` dataset.

#### Example

An example event for `endpoint_dlp` looks as following:

```json
{
    "@timestamp": "2023-10-16T22:55:48.000Z",
    "agent": {
        "ephemeral_id": "8455a4fe-aa90-48fd-9136-5bbf8e89473d",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zia.endpoint_dlp",
        "namespace": "ep",
        "type": "logs"
    },
    "device": {
        "model": {
            "identifier": "Model-2022"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "allow",
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection"
        ],
        "dataset": "zscaler_zia.endpoint_dlp",
        "id": "2",
        "ingested": "2024-07-04T12:05:26Z",
        "kind": "alert",
        "timezone": "GMT",
        "type": [
            "allowed"
        ]
    },
    "file": {
        "hash": {
            "md5": "938c2cc0dcc05f2b68c4287040cfcf71",
            "sha256": "076085239f3a10b8f387c4e5d4261abf8d109aa641be35a8d4ed2d775eb09612"
        },
        "path": "dest_path",
        "type": "file"
    },
    "host": {
        "hostname": "Dev 1",
        "name": "host",
        "os": {
            "platform": "Windows",
            "version": "Win-11"
        },
        "type": "WinUser"
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "hash": [
            "938c2cc0dcc05f2b68c4287040cfcf71",
            "076085239f3a10b8f387c4e5d4261abf8d109aa641be35a8d4ed2d775eb09612"
        ],
        "hosts": [
            "host",
            "Dev 1"
        ],
        "user": [
            "Administrator",
            "TempUser"
        ]
    },
    "rule": {
        "name": [
            "configured_rule"
        ]
    },
    "tags": [
        "forwarded",
        "zscaler_zia-endpoint_dlp"
    ],
    "user": {
        "name": "TempUser"
    },
    "zscaler_zia": {
        "endpoint_dlp": {
            "activity_type": "email_sent",
            "additional_info": "File already open by another application",
            "channel": "Network Drive Transfer",
            "confirm_action": "confirm",
            "confirm_just": "My manager approved it",
            "datacenter": {
                "city": "Atlanta",
                "country": "US",
                "name": "Georgia"
            },
            "day": "Mon",
            "day_of_month": 16,
            "department": "TempDept",
            "destination_type": "personal_cloud_storage",
            "device": {
                "appversion": "Ver-2199",
                "os": {
                    "type": "Windows"
                },
                "owner": "Administrator"
            },
            "dictionary": {
                "id": 8
            },
            "dictionary_names": [
                "[dlp]"
            ],
            "engine": {
                "id": 12
            },
            "engine_names": [
                "dlpengine"
            ],
            "event_time": "2023-10-16T22:55:48.000Z",
            "expected_action": "block",
            "feed_time": "2023-10-16T22:55:48.000Z",
            "file": {
                "doc_type": "Medical",
                "source_path": "source_path",
                "type": {
                    "name": "exe64"
                },
                "type_category": "PLS File (pls)"
            },
            "hour": 22,
            "identifier": "12",
            "item": {
                "destination_name": "nanolog",
                "name": "endpoint_dlp",
                "source_name": "endpoint",
                "type": "email_attachment"
            },
            "log_type": "dlp_incident",
            "minute": 55,
            "month": "Oct",
            "month_of_year": 10,
            "scan_time": 1210,
            "scanned_bytes": 290812,
            "second": 48,
            "severity": "High Severity",
            "source_type": "network_share",
            "timezone": "GMT",
            "year": 2023,
            "zdp_mode": "block mode"
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
| zscaler_zia.endpoint_dlp.action_taken | The action taken by Zscaler Data Protection. | keyword |
| zscaler_zia.endpoint_dlp.activity_type | The activity type. | keyword |
| zscaler_zia.endpoint_dlp.additional_info | Additional information. | keyword |
| zscaler_zia.endpoint_dlp.channel | The channel. | keyword |
| zscaler_zia.endpoint_dlp.confirm_action | The confirmation action by the user. | keyword |
| zscaler_zia.endpoint_dlp.confirm_just | The confirmation action justification by the user. | keyword |
| zscaler_zia.endpoint_dlp.counts | The number of hits for each of the DLP dictionaries. | long |
| zscaler_zia.endpoint_dlp.datacenter.city | The city where the data center is located. | keyword |
| zscaler_zia.endpoint_dlp.datacenter.country | The country where the data center is located. | keyword |
| zscaler_zia.endpoint_dlp.datacenter.name | The name of the data center. | keyword |
| zscaler_zia.endpoint_dlp.day | The day of the week. | keyword |
| zscaler_zia.endpoint_dlp.day_of_month | The day of the month. | long |
| zscaler_zia.endpoint_dlp.department | The name of the department. | keyword |
| zscaler_zia.endpoint_dlp.destination_type | The destination type. | keyword |
| zscaler_zia.endpoint_dlp.device.appversion | The device application version. | keyword |
| zscaler_zia.endpoint_dlp.device.hostname | The device host name. | keyword |
| zscaler_zia.endpoint_dlp.device.model | The device model. | keyword |
| zscaler_zia.endpoint_dlp.device.name | The device name. | keyword |
| zscaler_zia.endpoint_dlp.device.os.type | The device OS type. | keyword |
| zscaler_zia.endpoint_dlp.device.os.version | The device OS version. | keyword |
| zscaler_zia.endpoint_dlp.device.owner | The device owner. | keyword |
| zscaler_zia.endpoint_dlp.device.platform | The device platform. | keyword |
| zscaler_zia.endpoint_dlp.device.type | The device type. | keyword |
| zscaler_zia.endpoint_dlp.dictionary.id | The number of DLP dictionaries hit. | long |
| zscaler_zia.endpoint_dlp.dictionary_names | The DLP dictionary names. | keyword |
| zscaler_zia.endpoint_dlp.engine.id | The number of DLP engines hit. | long |
| zscaler_zia.endpoint_dlp.engine_names | The DLP engine names. | keyword |
| zscaler_zia.endpoint_dlp.event_time | The event time. | date |
| zscaler_zia.endpoint_dlp.expected_action | The expected action by ZDP. | keyword |
| zscaler_zia.endpoint_dlp.feed_time | The feed time. | date |
| zscaler_zia.endpoint_dlp.file.destination_path | The file destination path. | keyword |
| zscaler_zia.endpoint_dlp.file.doc_type | The file document type. | keyword |
| zscaler_zia.endpoint_dlp.file.md5 | The file MD5 hash. | keyword |
| zscaler_zia.endpoint_dlp.file.sha256 | The file SHA256 hash. | keyword |
| zscaler_zia.endpoint_dlp.file.source_path | The file source path. | keyword |
| zscaler_zia.endpoint_dlp.file.type.name | The file type. | keyword |
| zscaler_zia.endpoint_dlp.file.type_category | The file type category. | keyword |
| zscaler_zia.endpoint_dlp.hour | Hours. | long |
| zscaler_zia.endpoint_dlp.identifier | The unique DLP identifier. | keyword |
| zscaler_zia.endpoint_dlp.item.destination_name | The item destination name. | keyword |
| zscaler_zia.endpoint_dlp.item.name | The item name. | keyword |
| zscaler_zia.endpoint_dlp.item.source_name | The item source name. | keyword |
| zscaler_zia.endpoint_dlp.item.type | The item type. | keyword |
| zscaler_zia.endpoint_dlp.log_type | The type of record. | keyword |
| zscaler_zia.endpoint_dlp.minute | Minutes. | long |
| zscaler_zia.endpoint_dlp.month | The name of the month. | keyword |
| zscaler_zia.endpoint_dlp.month_of_year | The month of the year. | long |
| zscaler_zia.endpoint_dlp.obfuscated.department | The obfuscated version of the department name. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.device.hostname | The obfuscated version of the device host name. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.device.name | The obfuscated version of the device name. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.device.owner | The obfuscated version of the device owner. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.dlp.dictionary_names | The obfuscated version of the DLP dictionary names. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.dlp.engine_names | The obfuscated version of the DLP engine names. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.file.destination_path | The obfuscated version of the file destination path. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.file.source_path | The obfuscated version of the file source path. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.item.destination_names | The obfuscated version of the item destination name. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.item.name | The obfuscated version of the item name. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.item.source_names | The obfuscated version of the item source name. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.other_rule_labels | The obfuscated version of the other rule labels. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.triggered_rule_label | The obfuscated version of the triggered DLP rule. | keyword |
| zscaler_zia.endpoint_dlp.obfuscated.user | The obfuscated version of the username. | keyword |
| zscaler_zia.endpoint_dlp.other_rule_labels | The labels of other rules that were triggered. | keyword |
| zscaler_zia.endpoint_dlp.record.id | The unique record identifier. | keyword |
| zscaler_zia.endpoint_dlp.scan_time | The scan time in milliseconds. | long |
| zscaler_zia.endpoint_dlp.scanned_bytes | The scanned item size in bytes. | long |
| zscaler_zia.endpoint_dlp.second | Seconds. | long |
| zscaler_zia.endpoint_dlp.severity | The severity of the event. | keyword |
| zscaler_zia.endpoint_dlp.source_type | The source type. | keyword |
| zscaler_zia.endpoint_dlp.time | The log time. | date |
| zscaler_zia.endpoint_dlp.timezone | The time zone. | keyword |
| zscaler_zia.endpoint_dlp.triggered_rule_label | The DLP rule that was triggered. | keyword |
| zscaler_zia.endpoint_dlp.user | The username. | keyword |
| zscaler_zia.endpoint_dlp.year | Year. | long |
| zscaler_zia.endpoint_dlp.zdp_mode | The ZDP mode. | keyword |


### firewall

This is the `firewall` dataset.

#### Example

An example event for `firewall` looks as following:

```json
{
    "@timestamp": "2021-12-17T07:27:54.000Z",
    "agent": {
        "ephemeral_id": "4bb89723-7b9f-4ceb-9f00-cf2c4b142e7d",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zia.firewall",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 1734,
        "geo": {
            "country_iso_code": "Ireland"
        },
        "ip": [
            "0.0.0.0"
        ],
        "port": [
            443
        ]
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "drop",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zia.firewall",
        "duration": 486000000,
        "ingested": "2024-07-04T12:07:31Z",
        "kind": "event",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "machine9000"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.243.6:42432"
        }
    },
    "network": {
        "application": "http",
        "bytes": 20786,
        "protocol": "https",
        "transport": "tcp"
    },
    "observer": {
        "product": "ZIA",
        "type": "firewall",
        "vendor": "Zscaler"
    },
    "related": {
        "hosts": [
            "machine9000"
        ],
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "admin77",
            "some_user",
            "some_user@example.com"
        ]
    },
    "rule": {
        "name": [
            "Access Blocked"
        ]
    },
    "source": {
        "bytes": 19052,
        "ip": [
            "0.0.0.0"
        ],
        "port": [
            55018,
            0
        ]
    },
    "tags": [
        "forwarded",
        "zscaler_zia-firewall"
    ],
    "user": {
        "domain": "example.com",
        "email": "some_user@example.com",
        "name": "some_user"
    },
    "zscaler_zia": {
        "firewall": {
            "aggregate": "No",
            "client": {
                "destination": {
                    "ip": "0.0.0.0"
                },
                "source": {
                    "ip": "0.0.0.0"
                }
            },
            "department": "Unknown",
            "device": {
                "owner": "admin77"
            },
            "duration": {
                "average_duration": 486,
                "seconds": 0
            },
            "ip_category": "Test Name",
            "location_name": "TestLoc DB",
            "nat": "No",
            "server": {
                "destination": {
                    "ip": "0.0.0.0"
                },
                "source": {
                    "ip": "0.0.0.0"
                }
            },
            "session": {
                "count": 1
            },
            "stateful": "Yes",
            "tunnel": {
                "ip": "0.0.0.0",
                "type": "ZscalerClientConnector"
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
| zscaler_zia.firewall.action | The action that the service took on the transaction. | keyword |
| zscaler_zia.firewall.aggregate | Indicates whether the Firewall session is aggregated. | keyword |
| zscaler_zia.firewall.bypassed.session | Indicates whether the traffic bypassed the Zscaler Client Connector. | keyword |
| zscaler_zia.firewall.bypassed.time | The date and time when the traffic bypassed the Zscaler Client Connector. | date |
| zscaler_zia.firewall.bytes_in | The number of bytes sent from the server to the client. | long |
| zscaler_zia.firewall.client.destination.ip | The client destination IP address. | ip |
| zscaler_zia.firewall.client.destination.port | The client destination port. | long |
| zscaler_zia.firewall.client.domain | The client destination FDQN. | keyword |
| zscaler_zia.firewall.client.source.ip | The client source IP address. | ip |
| zscaler_zia.firewall.client.source.port | The client source port. | long |
| zscaler_zia.firewall.datacenter.city | The city where the data center is located. | keyword |
| zscaler_zia.firewall.datacenter.country | The country where the data center is located. | keyword |
| zscaler_zia.firewall.datacenter.name | The name of the data center. | keyword |
| zscaler_zia.firewall.day | The day of the week. | keyword |
| zscaler_zia.firewall.day_of_month | The day of the month. | long |
| zscaler_zia.firewall.department |  | keyword |
| zscaler_zia.firewall.dept | The department of the user. | keyword |
| zscaler_zia.firewall.destination.country | The abbreviated code of the country of the destination IP address. | keyword |
| zscaler_zia.firewall.device.appversion | The app version that the device app uses. | keyword |
| zscaler_zia.firewall.device.hostname | The host name of the device. | keyword |
| zscaler_zia.firewall.device.model | The model of the device. | keyword |
| zscaler_zia.firewall.device.name | The name of the device. | keyword |
| zscaler_zia.firewall.device.os.type | The OS type of the device. | keyword |
| zscaler_zia.firewall.device.os.version | The OS version that the device uses. | keyword |
| zscaler_zia.firewall.device.owner | The owner of the device. | keyword |
| zscaler_zia.firewall.duration.average_duration | The average session duration, in milliseconds, if the sessions were aggregated. | long |
| zscaler_zia.firewall.duration.milliseconds | The session or request duration in milliseconds. | long |
| zscaler_zia.firewall.duration.seconds | The session or request duration in seconds. | long |
| zscaler_zia.firewall.eedone | Indicates if the characters specified in the Feed Escape Character field of the NSS feed configuration page were hex encoded. | keyword |
| zscaler_zia.firewall.epochtime | The epoch time of the transaction. | date |
| zscaler_zia.firewall.external_device_id | The external device ID that associates a user’s device with the mobile device management (MDM) solution. | keyword |
| zscaler_zia.firewall.flow_type | The flow type of the transaction. | keyword |
| zscaler_zia.firewall.forward_gateway_name | The name of the gateway defined in a forwarding rule. | keyword |
| zscaler_zia.firewall.hour | Hours. | long |
| zscaler_zia.firewall.ip_category | The URL category that corresponds to the server IP address. | keyword |
| zscaler_zia.firewall.ip_protocol | The type of IP protocol. | keyword |
| zscaler_zia.firewall.ips.custom_signature | Indicates if a custom IPS signature rule was applied. | keyword |
| zscaler_zia.firewall.ips.rule_label | The name of the IPS policy that was applied to the Firewall session. | keyword |
| zscaler_zia.firewall.location | The name of the location from which the session was initiated. | keyword |
| zscaler_zia.firewall.location_name |  | keyword |
| zscaler_zia.firewall.login | The user's login name in email address format. | keyword |
| zscaler_zia.firewall.minutes | Minutes. | long |
| zscaler_zia.firewall.month | The name of the month. | keyword |
| zscaler_zia.firewall.month_of_year | The month of the year. | long |
| zscaler_zia.firewall.nat | Indicates if the destination NAT policy was applied. | keyword |
| zscaler_zia.firewall.nat_rule_label | The name of the destination NAT policy that was applied. | keyword |
| zscaler_zia.firewall.network.application | The network application that was accessed. | keyword |
| zscaler_zia.firewall.network.service | The network service that was used. | keyword |
| zscaler_zia.firewall.obfuscated.client_source_ip | The obfuscated version of the client source IP address. | keyword |
| zscaler_zia.firewall.obfuscated.device.name | The obfuscated version of the name of the device. | keyword |
| zscaler_zia.firewall.obfuscated.device.owner | The obfuscated version of the owner of the device. | keyword |
| zscaler_zia.firewall.obfuscated.forward_gateway_name | The obfuscated version of the gateway defined in a forwarding rule. | keyword |
| zscaler_zia.firewall.obfuscated.host_name | The obfuscated version of the host name of the device. | keyword |
| zscaler_zia.firewall.obfuscated.ip.category | The obfuscated version of the URL category that corresponds to the server IP address. | keyword |
| zscaler_zia.firewall.obfuscated.ips_rule_label | The obfuscated version of the name of the IPS policy that was applied to the Firewall session. | keyword |
| zscaler_zia.firewall.obfuscated.nat_label | The obfuscated version of the name of the destination NAT policy that was applied. | keyword |
| zscaler_zia.firewall.obfuscated.redirect_policy_name | The obfuscated version of the name of the redirect/forwarding policy. | keyword |
| zscaler_zia.firewall.obfuscated.rule_label | The obfuscated version of the name of the rule that was applied to the transaction. | keyword |
| zscaler_zia.firewall.obfuscated.zpa_app_segment | The obfuscated version of the ZPA application segment. | keyword |
| zscaler_zia.firewall.out_bytes | The number of bytes sent from the client to the server. | long |
| zscaler_zia.firewall.record.id | The record ID. | keyword |
| zscaler_zia.firewall.redirect_policy_name | The name of the redirect/forwarding policy. | keyword |
| zscaler_zia.firewall.rule | The name of the rule that was applied to the transaction. | keyword |
| zscaler_zia.firewall.rule_label |  | keyword |
| zscaler_zia.firewall.second | Seconds. | long |
| zscaler_zia.firewall.server.destination.ip | The server destination IP address. | ip |
| zscaler_zia.firewall.server.destination.port | The server destination port. | long |
| zscaler_zia.firewall.server.source.ip | The server source IP address. | ip |
| zscaler_zia.firewall.server.source.port | The server source port. | long |
| zscaler_zia.firewall.session.count | The number of sessions that were aggregated. | long |
| zscaler_zia.firewall.source_ip_country | The traffic's source country, which is determined by the client IP address location. | keyword |
| zscaler_zia.firewall.stateful | Indicates if the Firewall session is stateful. | keyword |
| zscaler_zia.firewall.threat.category | The category of the threat in the Firewall session by the IPS engine. | keyword |
| zscaler_zia.firewall.threat.name |  | keyword |
| zscaler_zia.firewall.threat_name | The name of the threat detected in the Firewall session by the IPS engine. | keyword |
| zscaler_zia.firewall.time | The time and date of the transaction. | date |
| zscaler_zia.firewall.timezone | The time zone. | keyword |
| zscaler_zia.firewall.tunnel.ip | The tunnel IP address of the client (source). | ip |
| zscaler_zia.firewall.tunnel.type | The traffic forwarding method used to send the traffic to the Firewall. | keyword |
| zscaler_zia.firewall.user |  | keyword |
| zscaler_zia.firewall.year | Year. | long |
| zscaler_zia.firewall.z_tunnel_version | The Z-Tunnel version. | keyword |
| zscaler_zia.firewall.zpa_app_segment | The name of the Zscaler Private Access (ZPA) application segment. | keyword |


### sandbox_report

This is the `sandbox_report` dataset.

#### Example

An example event for `sandbox_report` looks as following:

```json
{
    "@timestamp": "2024-07-04T12:08:18.143Z",
    "agent": {
        "ephemeral_id": "d12fe3a6-bd2e-4729-9303-bdbbc18f187e",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zia.sandbox_report",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "completed",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "zscaler_zia.sandbox_report",
        "duration": 454557000000,
        "ingested": "2024-07-04T12:08:30Z",
        "kind": "alert",
        "original": "{\"Classification\":{\"Category\":\"MALWARE_BOTNET\",\"DetectedMalware\":\"\",\"Max Score\":100,\"Score\":86,\"Type\":\"MALICIOUS\"},\"FileProperties\":{\"DigitalCerificate\":\"\",\"FileSize\":9810,\"FileType\":\"CMD\",\"Issuer\":\"\",\"MD5\":\"8350ded6d39df158e51d6cfbe36fb012\",\"RootCA\":\"\",\"SHA1\":\"f4dd1d176975c70ba8963ebc654a78a6e345cfb6\",\"SSDeep\":\"192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J\",\"Sha256\":\"aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee\"},\"Summary\":{\"Analysis\":\"0\",\"Category\":\"SCRIPT\",\"Duration\":454557,\"FileType\":\"CMD\",\"StartTime\":1509567511,\"Status\":\"COMPLETED\",\"TimeUnit\":\"ms\",\"Url\":\"\"},\"SystemSummary\":{\"Risk\":\"LOW\",\"Signature\":\"Allocates memory within range which is reserved for system DLLs\",\"SignatureSources\":[\"\",\"76F90000 page execute and read and write\"]}}",
        "risk_score": 86,
        "start": "2017-11-01T20:18:31.000Z",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "md5": "8350ded6d39df158e51d6cfbe36fb012",
            "sha1": "f4dd1d176975c70ba8963ebc654a78a6e345cfb6",
            "sha256": "aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee",
            "ssdeep": "192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J"
        },
        "size": 9810
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "8350ded6d39df158e51d6cfbe36fb012",
            "f4dd1d176975c70ba8963ebc654a78a6e345cfb6",
            "aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee",
            "192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "zscaler_zia-sandbox_report"
    ],
    "threat": {
        "indicator": {
            "type": "file"
        }
    },
    "zscaler_zia": {
        "sandbox_report": {
            "classification": {
                "category": "MALWARE_BOTNET",
                "max_score": 100,
                "score": 86,
                "type": "MALICIOUS"
            },
            "file_properties": {
                "file_size": 9810,
                "file_type": "CMD",
                "md5": "8350ded6d39df158e51d6cfbe36fb012",
                "sha1": "f4dd1d176975c70ba8963ebc654a78a6e345cfb6",
                "sha256": "aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee",
                "ssdeep": "192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J"
            },
            "summary": {
                "analysis": "0",
                "category": "SCRIPT",
                "duration": 454557,
                "file": {
                    "type": "CMD"
                },
                "start_time": "2017-11-01T20:18:31.000Z",
                "status": "COMPLETED",
                "time_unit": "ms"
            },
            "system_summary": {
                "risk": "LOW",
                "signature": "Allocates memory within range which is reserved for system DLLs",
                "signature_sources": [
                    "76F90000 page execute and read and write"
                ]
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
| zscaler_zia.sandbox_report.classification.category |  | keyword |
| zscaler_zia.sandbox_report.classification.detected_malware |  | keyword |
| zscaler_zia.sandbox_report.classification.max_score |  | double |
| zscaler_zia.sandbox_report.classification.score |  | double |
| zscaler_zia.sandbox_report.classification.type |  | keyword |
| zscaler_zia.sandbox_report.exploit.risk |  | keyword |
| zscaler_zia.sandbox_report.exploit.signature |  | keyword |
| zscaler_zia.sandbox_report.exploit.signature_sources |  | keyword |
| zscaler_zia.sandbox_report.file_properties.digital_cerificate |  | keyword |
| zscaler_zia.sandbox_report.file_properties.file_size |  | long |
| zscaler_zia.sandbox_report.file_properties.file_type |  | keyword |
| zscaler_zia.sandbox_report.file_properties.issuer |  | keyword |
| zscaler_zia.sandbox_report.file_properties.md5 |  | keyword |
| zscaler_zia.sandbox_report.file_properties.root_ca |  | keyword |
| zscaler_zia.sandbox_report.file_properties.sha1 |  | keyword |
| zscaler_zia.sandbox_report.file_properties.sha256 |  | keyword |
| zscaler_zia.sandbox_report.file_properties.ssdeep |  | keyword |
| zscaler_zia.sandbox_report.networking.risk |  | keyword |
| zscaler_zia.sandbox_report.networking.signature |  | keyword |
| zscaler_zia.sandbox_report.networking.signature_sources |  | keyword |
| zscaler_zia.sandbox_report.origin.country |  | keyword |
| zscaler_zia.sandbox_report.origin.language |  | keyword |
| zscaler_zia.sandbox_report.origin.risk |  | keyword |
| zscaler_zia.sandbox_report.persistence.risk |  | keyword |
| zscaler_zia.sandbox_report.persistence.signature |  | keyword |
| zscaler_zia.sandbox_report.persistence.signature_sources |  | keyword |
| zscaler_zia.sandbox_report.security_bypass.risk |  | keyword |
| zscaler_zia.sandbox_report.security_bypass.signature |  | keyword |
| zscaler_zia.sandbox_report.security_bypass.signature_sources |  | keyword |
| zscaler_zia.sandbox_report.stealth.risk |  | keyword |
| zscaler_zia.sandbox_report.stealth.signature |  | keyword |
| zscaler_zia.sandbox_report.stealth.signature_sources |  | keyword |
| zscaler_zia.sandbox_report.summary.analysis |  | keyword |
| zscaler_zia.sandbox_report.summary.category |  | keyword |
| zscaler_zia.sandbox_report.summary.duration |  | long |
| zscaler_zia.sandbox_report.summary.file.type |  | keyword |
| zscaler_zia.sandbox_report.summary.start_time |  | date |
| zscaler_zia.sandbox_report.summary.start_time_unix |  | date |
| zscaler_zia.sandbox_report.summary.status |  | keyword |
| zscaler_zia.sandbox_report.summary.time_unit |  | keyword |
| zscaler_zia.sandbox_report.summary.url |  | keyword |
| zscaler_zia.sandbox_report.system_summary.risk |  | keyword |
| zscaler_zia.sandbox_report.system_summary.signature |  | keyword |
| zscaler_zia.sandbox_report.system_summary.signature_sources |  | keyword |


### tunnel

This is the `tunnel` dataset.

#### Example

An example event for `tunnel` looks as following:

```json
{
    "@timestamp": "2021-12-30T11:20:12.000Z",
    "agent": {
        "ephemeral_id": "85f8a4ec-94a7-4111-9cab-36896851bb15",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zia.tunnel",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "81.2.69.143"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zia.tunnel",
        "id": "1111111111111111111",
        "ingested": "2024-07-04T12:10:30Z",
        "kind": "event",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.243.6:36470"
        }
    },
    "related": {
        "ip": [
            "81.2.69.143",
            "81.2.69.145"
        ]
    },
    "source": {
        "ip": "81.2.69.145",
        "port": 0
    },
    "tags": [
        "forwarded",
        "zscaler_zia-tunnel"
    ],
    "zscaler_zia": {
        "tunnel": {
            "action": {
                "type": "IPSec Phase2"
            },
            "authentication": {
                "algorithm": "HMAC-SHA-1"
            },
            "destination": {
                "end": {
                    "ip": "81.2.69.143"
                },
                "start": {
                    "ip": "81.2.69.143",
                    "port": 0
                }
            },
            "encryption": {
                "algorithm": "AES"
            },
            "ikeversion": "1",
            "life": {
                "bytes": 0,
                "time": 3600
            },
            "policy": {
                "protocol": "Any"
            },
            "protocol": "ESP",
            "source": {
                "end": {
                    "ip": "81.2.69.145"
                },
                "start": {
                    "ip": "81.2.69.145",
                    "port": 0
                }
            },
            "spi": "123456789",
            "type": "IPSEC IKEV 1",
            "user_ip": "81.2.69.145"
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
| zscaler_zia.tunnel.action.type | The action type. | keyword |
| zscaler_zia.tunnel.authentication.algorithm | The authentication algorithm. | keyword |
| zscaler_zia.tunnel.authentication.type | The authentication type. | keyword |
| zscaler_zia.tunnel.bytes.received | The bytes received in a 60-second sample window by Zscaler from the customer. | long |
| zscaler_zia.tunnel.bytes.sent | The bytes transmitted in a 60-second sample window from Zscaler to the customer. | long |
| zscaler_zia.tunnel.datetime | The date and time of the event. | date |
| zscaler_zia.tunnel.day | The day of the week. | keyword |
| zscaler_zia.tunnel.day_of_month | The day of the month. | long |
| zscaler_zia.tunnel.destination.end.ip | Phase 2 policy proposal - Destination IP end. | ip |
| zscaler_zia.tunnel.destination.port | The tunnel destination port. | long |
| zscaler_zia.tunnel.destination.start.ip | Phase 2 policy proposal - Destination IP start. | ip |
| zscaler_zia.tunnel.destination.start.port | Phase 2 policy proposal - Destination port start. | long |
| zscaler_zia.tunnel.destination.vip.address | The tunnel destination VIP address. | ip |
| zscaler_zia.tunnel.dpd_packets | The number of DPD packets received in a 60-second sample window. | long |
| zscaler_zia.tunnel.encryption.algorithm | The encryption algorithm. | keyword |
| zscaler_zia.tunnel.event | The tunnel status. | keyword |
| zscaler_zia.tunnel.event_reason | The reason for the tunnel status change. | keyword |
| zscaler_zia.tunnel.hour | Hours. | long |
| zscaler_zia.tunnel.ikeversion | The IKE version. | keyword |
| zscaler_zia.tunnel.life.bytes | Life bytes. | long |
| zscaler_zia.tunnel.life.time | The lifetime of IKE Phase 2 (seconds). | long |
| zscaler_zia.tunnel.locationname | The location name. | keyword |
| zscaler_zia.tunnel.minute | Minutes. | long |
| zscaler_zia.tunnel.month | The name of the month. | keyword |
| zscaler_zia.tunnel.month_of_year | The month of the year. | long |
| zscaler_zia.tunnel.obfuscated.location_name | The obfuscated version of the location name. | keyword |
| zscaler_zia.tunnel.obfuscated.vpn_credential_name | The obfuscated version of the VPN credential name for the IPSec tunnel. | keyword |
| zscaler_zia.tunnel.packets.received | The packets received in a 60-second sample window by Zscaler from the customer. | long |
| zscaler_zia.tunnel.packets.sent | The packets transmitted in a 60-second sample window from Zscaler to the customer. | long |
| zscaler_zia.tunnel.policy.protocol | Phase 2 policy proposal - Protocol. | keyword |
| zscaler_zia.tunnel.protocol | The IPSec tunnel protocol type. | keyword |
| zscaler_zia.tunnel.record.id | The unique record identifier for each log. | keyword |
| zscaler_zia.tunnel.second | Seconds. | long |
| zscaler_zia.tunnel.source.end.ip | Phase 2 policy proposal - Source IP end. | ip |
| zscaler_zia.tunnel.source.ip | The tunnel source IP address. | ip |
| zscaler_zia.tunnel.source.port | The tunnel source port. | long |
| zscaler_zia.tunnel.source.start.ip | Phase 2 policy proposal - Source IP start. | ip |
| zscaler_zia.tunnel.source.start.port | Phase 2 policy proposal - Source port start. | long |
| zscaler_zia.tunnel.spi | The Security Parameter Index. | keyword |
| zscaler_zia.tunnel.spi_in | The initiator cookie. | keyword |
| zscaler_zia.tunnel.spi_out | The responder cookie. | keyword |
| zscaler_zia.tunnel.timezone | The time zone. | keyword |
| zscaler_zia.tunnel.type | The tunnel type. | keyword |
| zscaler_zia.tunnel.user_ip |  | ip |
| zscaler_zia.tunnel.vendor.name | The vendor name of the edge device. | keyword |
| zscaler_zia.tunnel.vpn_credential_name | The VPN credential name for the IPSec tunnel. | keyword |
| zscaler_zia.tunnel.year | Year. | long |


### web

This is the `web` dataset.

#### Example

An example event for `web` looks as following:

```json
{
    "@timestamp": "2021-12-31T08:08:08.000Z",
    "agent": {
        "ephemeral_id": "f97a3a33-4778-4f8f-a98e-42c9d5997a3b",
        "id": "3afa5c75-c6e3-41a8-a773-ff6a6356f7b1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "data_stream": {
        "dataset": "zscaler_zia.web",
        "namespace": "98923",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3afa5c75-c6e3-41a8-a773-ff6a6356f7b1",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "action": "blocked",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "zscaler_zia.web",
        "ingested": "2024-07-17T11:07:47Z",
        "kind": "event",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "file": {
        "type": "file"
    },
    "host": {
        "name": "testmachine35"
    },
    "http": {
        "request": {
            "bytes": 600,
            "method": "CONNECT"
        },
        "response": {
            "bytes": 65
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
            "testmachine35"
        ],
        "user": [
            "administrator1",
            "test",
            "test@example.com"
        ]
    },
    "rule": {
        "name": [
            "Zscaler Proxy Traffic"
        ]
    },
    "tags": [
        "forwarded",
        "zscaler_zia-web"
    ],
    "user": {
        "domain": "example.com",
        "email": "test@example.com",
        "name": "test"
    },
    "zscaler_zia": {
        "web": {
            "app": {
                "class": "General Browsing",
                "name": "General Browsing"
            },
            "content_type": "Other",
            "department": "Unknown",
            "device": {
                "owner": "administrator1"
            },
            "location": "Test DB",
            "response": {
                "code": "200"
            },
            "risk": {
                "score": 0
            },
            "rule": {
                "type": "FwFilter"
            },
            "url": {
                "category": {
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
| zscaler_zia.web.action | The action that the service took on the transaction. | keyword |
| zscaler_zia.web.alpn_protocol | The Application-Layer Protocol Negotiation (ALPN) protocol. | keyword |
| zscaler_zia.web.app.class | The web application class of the application that was accessed. | keyword |
| zscaler_zia.web.app.name | The name of the cloud application. | keyword |
| zscaler_zia.web.app.risk_score | The computed or assigned risk index for the cloud application. | keyword |
| zscaler_zia.web.app.rule_label | The name of the rule that was applied to the application. | keyword |
| zscaler_zia.web.bandwidth_class_name | The name of the bandwidth class. | keyword |
| zscaler_zia.web.bandwidth_rule_name | The name of the bandwidth rule. | keyword |
| zscaler_zia.web.bandwidth_throttle | Indicates whether the transaction was throttled due to a configured bandwidth policy. | keyword |
| zscaler_zia.web.bypassed.time | The date and time when the traffic bypassed the Zscaler Client Connector. | date |
| zscaler_zia.web.bypassed.traffic | Indicates whether the traffic bypassed the Zscaler Client Connector or not. | keyword |
| zscaler_zia.web.client.cipher | The negotiated cipher suite for communication between the client and Zscaler. | keyword |
| zscaler_zia.web.client.cipher_reuse | Client cipher reuse information. | keyword |
| zscaler_zia.web.client.internet.ip | The client's Internet (NATed Public) IP address. | ip |
| zscaler_zia.web.client.ip | The IP address of the user. | ip |
| zscaler_zia.web.client.public_ip | The client public IP address. | ip |
| zscaler_zia.web.client.source_port | The client source port. | long |
| zscaler_zia.web.client.ssl.fail_count | The number of failed client SSL handshake attempts. | long |
| zscaler_zia.web.client.ssl.fail_reason | The reason for the client SSL handshake failure. | keyword |
| zscaler_zia.web.client.tls_version | The TLS version used for communication between the client and Zscaler. | keyword |
| zscaler_zia.web.cloud_name | The name of the Zscaler cloud. | keyword |
| zscaler_zia.web.company | The name of the company. | keyword |
| zscaler_zia.web.content_type | The name of the content type. | keyword |
| zscaler_zia.web.datacenter.city | The city where the data center is located. | keyword |
| zscaler_zia.web.datacenter.country | The country where the data center is located. | keyword |
| zscaler_zia.web.datacenter.name | The name of the data center. | keyword |
| zscaler_zia.web.day | The day of the week. | keyword |
| zscaler_zia.web.day_of_month | The day of the month. | long |
| zscaler_zia.web.department | The department of the user. | keyword |
| zscaler_zia.web.device.appversion | The app version the device uses. | keyword |
| zscaler_zia.web.device.hostname | The hostname of the device. | keyword |
| zscaler_zia.web.device.model | The model of the device. | keyword |
| zscaler_zia.web.device.name | The name of the device. | keyword |
| zscaler_zia.web.device.os.type | The OS type of the device. | keyword |
| zscaler_zia.web.device.os.version | The OS version the device uses. | keyword |
| zscaler_zia.web.device.owner | The owner of the device. | keyword |
| zscaler_zia.web.device.type | The type of device. | keyword |
| zscaler_zia.web.df.host.head | The field contains HTTP/S transactions that indicate domain fronting due to an FQDN mismatch between the request URL and the request's host header. | keyword |
| zscaler_zia.web.df.host.name | An optional field that contains the TLS connection's Server Name Indication (SNI). | keyword |
| zscaler_zia.web.dlp.dictionaries.hit_count | The number of hits for each of the dictionaries that were matched in the transaction. | keyword |
| zscaler_zia.web.dlp.dictionaries.name | The DLP dictionaries that were matched. | keyword |
| zscaler_zia.web.dlp.engine | The DLP engine that was matched. | keyword |
| zscaler_zia.web.dlp.identifier | The unique identifier of the DLP incident. | keyword |
| zscaler_zia.web.dlp.md5 | The MD5 hash of the transaction. | keyword |
| zscaler_zia.web.dlp.rule.name | The name of the DLP rule applied to the transaction. | keyword |
| zscaler_zia.web.eedone | Indicates if the characters specified in the Feed Escape Character field of the NSS feed configuration page were hex encoded. | keyword |
| zscaler_zia.web.epochtime | The epoch time of the transaction. | date |
| zscaler_zia.web.external.device.id | The external device ID that associates a user’s device with the mobile device management (MDM) solution. | keyword |
| zscaler_zia.web.file.class | The class of file downloaded during the transaction. | keyword |
| zscaler_zia.web.file.name | The name of downloaded files during the transaction. | keyword |
| zscaler_zia.web.file.subtype | Applicable to the web traffic processed via Isolation. | keyword |
| zscaler_zia.web.file.type | The type of file downloaded during the transaction. | keyword |
| zscaler_zia.web.flow_type | The flow type of the transaction. | keyword |
| zscaler_zia.web.forward_gateway.ip | The IP address of the gateway used. | ip |
| zscaler_zia.web.forward_gateway.name | The name of the gateway defined in a forwarding rule. | keyword |
| zscaler_zia.web.forward_type | The type of forwarding method used. | keyword |
| zscaler_zia.web.host | The destination hostname. | keyword |
| zscaler_zia.web.hour | Hours. | long |
| zscaler_zia.web.is_ssl_certificate_expired | Indicates whether the certificate presented by the server is expired or not. | keyword |
| zscaler_zia.web.is_ssl_certificate_selfsigned | Indicates whether the certificate presented by the server to the ZIA Public Service Edge was self-signed. | keyword |
| zscaler_zia.web.is_ssl_certificate_untrusted | Indicates whether the server certificate is signed by a Zscaler-trusted certificate authority or not. | keyword |
| zscaler_zia.web.key_protection_type | Indicates whether an HSM Protection or a Software Protection intermediate CA certificate is used for the TLS interception. | keyword |
| zscaler_zia.web.location | The gateway location or sub-location of the source. | keyword |
| zscaler_zia.web.login | The user's login name in email address format. | keyword |
| zscaler_zia.web.malware.category | The category of malware that was detected in the transaction. | keyword |
| zscaler_zia.web.malware.class | The class of malware that was detected in the transaction. | keyword |
| zscaler_zia.web.md5_hash | The MD5 hash of the malware file that was detected in the transaction, or the MD5 of the file that was sent for analysis to the Sandbox engine. | keyword |
| zscaler_zia.web.minute | Minutes. | long |
| zscaler_zia.web.mobile.application.category | The category of the mobile app. | keyword |
| zscaler_zia.web.mobile.application.name | The name of the mobile app. | keyword |
| zscaler_zia.web.mobile.dev.type | The type of mobile device. | keyword |
| zscaler_zia.web.module | The web application class of the application that was accessed. | keyword |
| zscaler_zia.web.month | The name of the month. | keyword |
| zscaler_zia.web.month_of_year | The month of the year. | long |
| zscaler_zia.web.nss.service.ip | The service IP address of the NSS. | ip |
| zscaler_zia.web.obfuscated.app_rule_label | The obfuscated version of the name of the rule that was applied to the application. | keyword |
| zscaler_zia.web.obfuscated.bendwidth.class_name | The obfuscated version of the name of the bandwidth class. | keyword |
| zscaler_zia.web.obfuscated.client.ip | The obfuscated version of the IP address of the user. | keyword |
| zscaler_zia.web.obfuscated.client.public.ip | The obfuscated version of the client public IP address. | keyword |
| zscaler_zia.web.obfuscated.device.host_name | The obfuscated version of the hostname of the device. | keyword |
| zscaler_zia.web.obfuscated.device.name | The obfuscated version of the name of the device. | keyword |
| zscaler_zia.web.obfuscated.device.owner | The obfuscated version of the owner of the device. | keyword |
| zscaler_zia.web.obfuscated.dlp.dictionaries | The obfuscated version of the DLP dictionaries that were matched. | keyword |
| zscaler_zia.web.obfuscated.dlp.engine | The obfuscated version of the DLP engine that was matched. | keyword |
| zscaler_zia.web.obfuscated.dlp.rule.name | The obfuscated version of the name of the DLP rule that was applied. | keyword |
| zscaler_zia.web.obfuscated.forward_gateway_name | The obfuscated version of the gateway defined in a forwarding rule. | keyword |
| zscaler_zia.web.obfuscated.login | The obfuscated version of the user's login name. | keyword |
| zscaler_zia.web.obfuscated.rule.name | The obfuscated version of the name of the redirect/forwarding policy. | keyword |
| zscaler_zia.web.obfuscated.url.category | The obfuscated version of the category of the destination URL. | keyword |
| zscaler_zia.web.obfuscated.url.filter_rule_label | The obfuscated version of the name of the rule that was applied to the URL filter. | keyword |
| zscaler_zia.web.obfuscated.zpa_app_segment | The obfuscated version of the ZPA application segment. | keyword |
| zscaler_zia.web.policy.reason | The SSL policy reasons. | keyword |
| zscaler_zia.web.product_version | The current version of the product. | keyword |
| zscaler_zia.web.prototype | The protocol type of the transaction. | keyword |
| zscaler_zia.web.reason | The action that the service took and the policy that was applied. | keyword |
| zscaler_zia.web.record.id | The unique record identifier for each log. | keyword |
| zscaler_zia.web.redirect_policy_name | The name of the redirect/forwarding policy. | keyword |
| zscaler_zia.web.referer.host | The hostname of the referer URL. | keyword |
| zscaler_zia.web.referer.name | The HTTP referer URL. | keyword |
| zscaler_zia.web.referer.path | The HTTP referer path. | keyword |
| zscaler_zia.web.request.header_size | The size of the HTTP request header in bytes. | long |
| zscaler_zia.web.request.method | The HTTP request method. | keyword |
| zscaler_zia.web.request.payload | The size of the HTTP request payload. | long |
| zscaler_zia.web.request.size | The request size in bytes. | long |
| zscaler_zia.web.request.version | The HTTP request version. | keyword |
| zscaler_zia.web.response.code | The HTTP response code sent to the client. | keyword |
| zscaler_zia.web.response.header_size | The size of the HTTP response header in bytes. | long |
| zscaler_zia.web.response.payload | The size of the HTTP response payload. | long |
| zscaler_zia.web.response.size | The total size of the HTTP response in bytes. | long |
| zscaler_zia.web.response.version | The HTTP response version. | keyword |
| zscaler_zia.web.risk.score | The Page Risk Index score of the destination URL. | double |
| zscaler_zia.web.rule.name | The name of the rule that was applied to the transaction. | keyword |
| zscaler_zia.web.rule.type | The type of policy. | keyword |
| zscaler_zia.web.second | Seconds. | long |
| zscaler_zia.web.server.certificate.validation.period | The expiration of the server certificate. | keyword |
| zscaler_zia.web.server.certificate_validation_chain | The validation of the certificate chain. | keyword |
| zscaler_zia.web.server.certificate_validation_type | The validation method of the server certificate. | keyword |
| zscaler_zia.web.server.cipher | The negotiated cipher suite for communication between Zscaler and the server. | keyword |
| zscaler_zia.web.server.cipher_reuse | Server cipher reuse information. | keyword |
| zscaler_zia.web.server.ip | The destination server IP address. | ip |
| zscaler_zia.web.server.ocsp_result | The OCSP result/certificate revocation result. | keyword |
| zscaler_zia.web.server.tls_version | The TLS/SSL version used for communication between the ZIA Public Service Edge and the server. | keyword |
| zscaler_zia.web.server.wildcard_certificate | The server wildcard certificate. | keyword |
| zscaler_zia.web.sha256 | The hash of identical files. | keyword |
| zscaler_zia.web.ssl_decrypted | Indicates whether the transaction was SSL inspected or not. | keyword |
| zscaler_zia.web.threat.name | The name of the threat that was detected in the transaction. | keyword |
| zscaler_zia.web.threat.severity | The severity of the threat that was detected in the transaction. | keyword |
| zscaler_zia.web.throttle.request_size | The throttled transaction size in the Uplink direction (Upload) in bytes. | long |
| zscaler_zia.web.throttle.response_size | The throttled transaction size in the Downlink direction (Download) in bytes. | long |
| zscaler_zia.web.time | The time and date of the transaction. | date |
| zscaler_zia.web.timezone | The time zone. | keyword |
| zscaler_zia.web.total.size | The total size of the HTTP transaction in bytes. | long |
| zscaler_zia.web.traffic_redirect_method | The traffic forwarding method to ZIA Public Service Edges. | keyword |
| zscaler_zia.web.unscannable.type | The unscannable file type. | keyword |
| zscaler_zia.web.upload.doc.type_name | The type of document uploaded or downloaded during the transaction. | keyword |
| zscaler_zia.web.upload.file.class | The class of file uploaded during the transaction. | keyword |
| zscaler_zia.web.upload.file.name | The name of uploaded files during the transaction. | keyword |
| zscaler_zia.web.upload.file.subtype | The subtype of the uploaded file (extension name). | keyword |
| zscaler_zia.web.upload.file.type | The type of file uploaded during the transaction. | keyword |
| zscaler_zia.web.url.category.sub | The category of the destination URL. | keyword |
| zscaler_zia.web.url.category.super | The super category of the destination URL. | keyword |
| zscaler_zia.web.url.category_method | Refers to the source of the URL's category. | keyword |
| zscaler_zia.web.url.class | The class of the destination URL. | keyword |
| zscaler_zia.web.url.filter_rule_label | The name of the rule that was applied to the URL filter. | keyword |
| zscaler_zia.web.url.name | The destination URL. | keyword |
| zscaler_zia.web.url.path | The destination URL path. | keyword |
| zscaler_zia.web.user_agent.class | The user agent class. | keyword |
| zscaler_zia.web.user_agent.name | The full user agent string for both known and unknown agents. | keyword |
| zscaler_zia.web.user_agent.token | The user agent token. | keyword |
| zscaler_zia.web.user_location_name | Applicable to the web traffic processed via Isolation. | keyword |
| zscaler_zia.web.year | Year. | long |
| zscaler_zia.web.z_tunnel_version | The Z-Tunnel version. | keyword |
| zscaler_zia.web.zpa_app_segment | The name of the Zscaler Private Access (ZPA) application segment. | keyword |

