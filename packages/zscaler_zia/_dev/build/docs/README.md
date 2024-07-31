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
            - **SIEM IP Address**: Enter the IP address of the {{ url "fleet-overview" "Elastic agent" }} you’ll be assigning the Zscaler integration to.
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

Zscaler response format (v1):
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

Zscaler response format (v1):
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

Zscaler response format (v1):
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

Zscaler response format (v1):
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

Zscaler response format (v1):
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

Zscaler response format (v1):
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

Zscaler response format (v2):
```
\{"sourcetype":"zscalernss-web","event":\{"time":"%s{time}","cloudname":"%s{cloudname}","host":"%s{host}","serverip":"%s{sip}","external_devid":"%s{external_devid}","devicemodel":"%s{devicemodel}","action":"%s{action}","recordid":"%d{recordid}","reason":"%s{reason}","threatseverity":"%s{threatseverity}","tz":"%s{tz}","filesubtype":"%s{filesubtype}","upload_filesubtype":"%s{upload_filesubtype}","sha256":"%s{sha256}","bamd5":"%s{bamd5}","filename":"%s{filename}","upload_filename":"%s{upload_filename}","filetype":"%s{filetype}","devicename":"%s{devicename}","devicehostname":"%s{devicehostname}","deviceostype":"%s{deviceostype}","deviceosversion":"%s{deviceosversion}","devicetype":"%s{devicetype}","reqsize":"%d{reqsize}","reqmethod":"%s{reqmethod}","refererurl":"%s{referer}","respsize":"%d{respsize}","respcode":"%s{respcode}","reqversion":"%s{reqversion}","respversion":"%s{respversion}","proto":"%s{proto}","company":"%s{company}","dlpmd5":"%s{dlpmd5}","apprulelabel":"%s{apprulelabel}","dlprulename":"%s{dlprulename}","rulelabel":"%s{rulelabel}","urlfilterrulelabel":"%s{urlfilterrulelabel}","cltip":"%s{cip}","cltintip":"%s{cintip}","cltsourceport":"%d{clt_sport}","threatname":"%s{threatname}","cltsslcipher":"%s{clientsslcipher}","clttlsversion":"%s{clienttlsversion}","eurl":"%s{eurl}","url":"%s{url}","useragent":"%s{ua}","login":"%s{login}","applayerprotocol":"%s{alpnprotocol}","appclass":"%s{appclass}","appname":"%s{appname}","appriskscore":"%s{app_risk_score}","bandwidthclassname":"%s{bwclassname}","bandwidthrulename":"%s{bwrulename}","bwthrottle":"%s{bwthrottle}","bypassedtime":"%s{bypassed_etime}","bypassedtraffic":"%d{bypassed_traffic}","cltsslsessreuse":"%s{clientsslsessreuse}","cltpubip":"%s{cpubip}","cltsslfailcount":"%d{cltsslfailcount}","cltsslfailreason":"%s{cltsslfailreason}","contenttype":"%s{contenttype}","datacentercity":"%s{datacentercity}","datacentercountry":"%s{datacentercountry}","datacenter":"%s{datacenter}","day":"%s{day}","day_of_month":"%02d{dd}","dept":"%s{dept}","deviceappversion":"%s{deviceappversion}","deviceowner":"%s{deviceowner}","df_hosthead":"%s{df_hosthead}","df_hostname":"%s{df_hostname}","dlpdicthitcount":"%s{dlpdicthitcount}","dlpdict":"%s{dlpdict}","dlpeng":"%s{dlpeng}","dlpidentifier":"%d{dlpidentifier}","eedone":"%s{eedone}","epochtime":"%d{epochtime}","fileclass":"%s{fileclass}","flow_type":"%s{flow_type}","forward_gateway_ip":"%s{fwd_gw_ip}","forward_gateway_name":"%s{fwd_gw_name}","forward_type":"%s{fwd_type}","hour":"%02d{hh}","is_sslexpiredca":"%s{is_sslexpiredca}","is_sslselfsigned":"%s{is_sslselfsigned}","is_ssluntrustedca":"%s{is_ssluntrustedca}","keyprotectiontype":"%s{keyprotectiontype}","location":"%s{location}","malwarecategory":"%s{malwarecat}","malwareclass":"%s{malwareclass}","minute":"%02d{mm}","mobappcategory":"%s{mobappcat}","mobappname":"%s{mobappname}","mobdevtype":"%s{mobdevtype}","module":"%s{module}","month":"%s{mon}","month_of_year":"%02d{mth}","nssserviceip":"%s{nsssvcip}","oapprulelabel":"%s{oapprulelabel}","obwclassname":"%s{obwclassname}","ocip":"%d{ocip}","ocpubip":"%d{ocpubip}","odevicehostname":"%s{odevicehostname}","odevicename":"%s{odevicename}","odeviceowner":"%s{odeviceowner}","odlpdict":"%s{odlpdict}","odlpeng":"%s{odlpeng}","odlprulename":"%s{odlprulename}","ofwd_gw_name":"%s{ofwd_gw_name}","ologin":"%s{ologin}","ordr_rulename":"%s{ordr_rulename}","ourlcat":"%s{ourlcat}","ourlfilterrulelabel":"%s{ourlfilterrulelabel}","ozpa_app_seg_name":"%s{ozpa_app_seg_name}","externalsslpolicyreason":"%s{externalspr}","productversion":"%s{productversion}","rdr_rulename":"%s{rdr_rulename}","refererhost":"%s{refererhost}","reqheadersize":"%d{reqhdrsize}","reqdatasize":"%d{reqdatasize}","respheadersize":"%d{resphdrsize}","respdatasize":"%d{respdatasize}","riskscore":"%d{riskscore}","ruletype":"%s{ruletype}","second":"%02d{ss}","srvcertchainvalpass":"%s{srvcertchainvalpass}","srvcertvalidationtype":"%s{srvcertvalidationtype}","srvcertvalidityperiod":"%s{srvcertvalidityperiod}","srvsslcipher":"%s{srvsslcipher}","serversslsessreuse":"%s{serversslsessreuse}","srvocspresult":"%s{srvocspresult}","srvtlsversion":"%s{srvtlsversion}","srvwildcardcert":"%s{srvwildcardcert}","ssldecrypted":"%s{ssldecrypted}","throttlereqsize":"%d{throttlereqsize}","throttlerespsize":"%d{throttlerespsize}","totalsize":"%d{totalsize}","trafficredirectmethod":"%s{trafficredirectmethod}","unscannabletype":"%s{unscannabletype}","upload_doctypename":"%s{upload_doctypename}","upload_fileclass":"%s{upload_fileclass}","upload_filetype":"%s{upload_filetype}","urlcatmethod":"%s{urlcatmethod}","urlsubcat":"%s{urlcat}","urlsupercat":"%s{urlsupercat}","urlclass":"%s{urlclass}","useragentclass":"%s{uaclass}","useragenttoken":"%s{ua_token}","userlocationname":"%s{userlocationname}","year":"%04d{yyyy}","ztunnelversion":"%s{ztunnelversion}","zpa_app_seg_name":"%s{zpa_app_seg_name}"\}\}
```

Sample Response:
```json
{"sourcetype":"zscalernss-web","event":{"time":"Mon Oct 16 22:55:48 2023","cloudname":"zscaler.net","host":"mail.google.com","serverip":"1.128.0.0","external_devid":"1234","devicemodel":"20L8S7WC08","action":"Allowed","recordid":123456789,"reason":"File Attachment Cautioned","threatseverity":"Critical (90–100)","tz":"GMT","filesubtype":"exe","upload_filesubtype":"rar","sha256":"81ec78bc8298568bb5ea66d3c2972b670d0f7459b6cdbbcaacce90ab417ab15c","bamd5":"196a3d797bfee07fe4596b69f4ce1141","filename":"nssfeed.txt","upload_filename":"nssfeed.exe","filetype":"RAR Files","devicename":"PC11NLPA:5F08D97BBF43257A8FB4BBF4061A38AE324EF734","devicehostname":"THINKPADSMITH","deviceostype":"iOS","deviceosversion":"Version 10.14.2 (Build 18C54)","devicetype":"Zscaler Client Connector","reqsize":1300,"reqmethod":"invalid","refererurl":"www.example.com","respsize":10500,"respcode":"100","reqversion":"1.1","respversion":"1","proto":"HTTP","company":"Zscaler","dlpmd5":"154f149b1443fbfa8c121d13e5c019a1","apprulelabel":"File_Sharing_1","dlprulename":"DLP_Rule_1","rulelabel":"URL_Filtering_1","urlfilterrulelabel":"URL_Filtering_2","cltip":"81.2.69.144","cltintip":"89.160.20.128","cltsourceport":12345,"threatname":"EICAR Test File","cltsslcipher":"SSL3_CK_RSA_NULL_MD5","clttlsversion":"SSL2","eurl":"www.trythisencodeurl.com/index","url":"www.trythisencodeurl.com/index","useragent":"Mozilla/5.0","login":"jdoe@safemarch.com","applayerprotocol":"FTP","appclass":"Administration","appname":"Adobe Connect","appriskscore":"1","bandwidthclassname":"Entertainment","bandwidthrulename":"Office 365","bwthrottle":"Yes","bypassedtime":"Mon Oct 16 22:55:48 2023","bypassedtraffic":"1","cltsslsessreuse":"Unknown","cltpubip":"175.16.199.0","cltsslfailcount":100,"cltsslfailreason":"Bad Record Mac","contenttype":"application/vnd_apple_keynote","datacentercity":"Sa","datacentercountry":"US","datacenter":"CA Client Node DC","day":"Mon","day_of_month":16,"dept":"Sales","deviceappversion":"1.128.0.0","deviceowner":"jsmith","df_hosthead":"df_hosthead","df_hostname":"df_hostname","dlpdicthitcount":"4","dlpdict":"Credit Cards","dlpeng":"HIPAA","dlpidentifier":6646484838839026000,"eedone":"Yes","epochtime":1578128400,"fileclass":"Active Web Contents","flow_type":"Direct","forward_gateway_ip":"10.1.1.1","forward_gateway_name":"FWD_1","forward_type":"Direct","hour":22,"is_sslexpiredca":"Yes","is_sslselfsigned":"Yes","is_ssluntrustedca":"Pass","keyprotectiontype":"HSM Protection","location":"Headquarters","malwarecategory":"Adware","malwareclass":"Sandbox","minute":55,"mobappcategory":"Communication","mobappname":"Amazon","mobdevtype":"Google Android","module":"Administration","month":"Oct","month_of_year":10,"nssserviceip":"192.168.2.200","oapprulelabel":"5300295980","obwclassname":"10831489","ocip":6200694987,"ocpubip":624054738,"odevicehostname":"2168890624","odevicename":"2175092224","odeviceowner":"10831489","odlpdict":"10831489","odlpeng":"4094304256","odlprulename":"6857275752","ofwd_gw_name":"8794487099","ologin":"4094304256","ordr_rulename":"3399565100","ourlcat":"7956407282","ourlfilterrulelabel":"4951704103","ozpa_app_seg_name":"7648246731","externalsslpolicyreason":"Blocked","productversion":"5.0.902.95524_04","rdr_rulename":"FWD_Rule_1","refererhost":"www.example.com for http://www.example.com/index.html","reqheadersize":300,"reqdatasize":1000,"respheadersize":500,"respdatasize":10000,"riskscore":10,"ruletype":"File Type Control","second":48,"srvcertchainvalpass":"Unknown","srvcertvalidationtype":"EV (Extended Validation)","srvcertvalidityperiod":"Short","srvsslcipher":"SSL3_CK_RSA_NULL_MD5","serversslsessreuse":"Unknown","srvocspresult":"Good","srvtlsversion":"SSL2","srvwildcardcert":"Unknown","ssldecrypted":"Yes","throttlereqsize":5,"throttlerespsize":7,"totalsize":11800,"trafficredirectmethod":"DNAT (Destination Translation)","unscannabletype":"Encrypted File","upload_doctypename":"Corporate Finance","upload_fileclass":"upload_fileclass","upload_filetype":"RAR Files","urlcatmethod":"Database A","urlsubcat":"Entertainment","urlsupercat":"Travel","urlclass":"Bandwidth Loss","useragentclass":"Firefox","useragenttoken":"Google Chrome (0.x)","userlocationname":"userlocationname","year":2023,"ztunnelversion":"ZTUNNEL_1_0","zpa_app_seg_name":"ZPA_test_app_segment"}}
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

{{event "alerts"}}

{{fields "alerts"}}

### audit

This is the `audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### dns

This is the `dns` dataset.

#### Example

{{event "dns"}}

{{fields "dns"}}

### endpoint_dlp

This is the `endpoint_dlp` dataset.

#### Example

{{event "endpoint_dlp"}}

{{fields "endpoint_dlp"}}

### firewall

This is the `firewall` dataset.

#### Example

{{event "firewall"}}

{{fields "firewall"}}

### sandbox_report

This is the `sandbox_report` dataset.

#### Example

{{event "sandbox_report"}}

{{fields "sandbox_report"}}

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
