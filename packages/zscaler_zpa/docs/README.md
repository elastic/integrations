# Zscaler ZPA

This integration is for Zscaler Private Access logs. It can be used
to receive logs sent by LSS Log Receiver on respective TCP ports.

The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`zscaler_zpa.<data-stream-name>.*`.

## Setup steps

1. Enable the integration with the TCP input.
2. Configure the Zscaler LSS Log Receiver to send logs to the Elastic Agent
that is running this integration. See [_Setup Log Receiver_](https://help.zscaler.com/zpa/configuring-log-receiver). Use the IP address/hostname of the Elastic Agent as the 'Log Receiver Domain or IP Address', and use the listening port of the Elastic Agent as the 'TCP Port' on the _Add Log Receiver_ configuration screen.
3. *Please make sure to use the given response formats.*

## Compatibility

This package has been tested against `Zscaler Private Access Client Connector version 3.7.1.44`

## Documentation and configuration

### App Connector Status Logs

Default port: _9015_

Vendor documentation: https://help.zscaler.com/zpa/about-connector-status-log-fields

Zscaler response format:  
```
{"LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"SessionID": %j{SessionID},"SessionType": %j{SessionType},"SessionStatus": %j{SessionStatus},"Version": %j{Version},"Platform": %j{Platform},"ZEN": %j{ZEN},"Connector": %j{Connector},"ConnectorGroup": %j{ConnectorGroup},"PrivateIP": %j{PrivateIP},"PublicIP": %j{PublicIP},"Latitude": %f{Latitude},"Longitude": %f{Longitude},"CountryCode": %j{CountryCode},"TimestampAuthentication": %j{TimestampAuthentication:iso8601},"TimestampUnAuthentication": %j{TimestampUnAuthentication:iso8601},"CPUUtilization": %d{CPUUtilization},"MemUtilization": %d{MemUtilization},"ServiceCount": %d{ServiceCount},"InterfaceDefRoute": %j{InterfaceDefRoute},"DefRouteGW": %j{DefRouteGW},"PrimaryDNSResolver": %j{PrimaryDNSResolver},"HostUpTime": %j{HostUpTime},"ConnectorUpTime": %j{ConnectorUpTime},"NumOfInterfaces": %d{NumOfInterfaces},"BytesRxInterface": %d{BytesRxInterface},"PacketsRxInterface": %d{PacketsRxInterface},"ErrorsRxInterface": %d{ErrorsRxInterface},"DiscardsRxInterface": %d{DiscardsRxInterface},"BytesTxInterface": %d{BytesTxInterface},"PacketsTxInterface": %d{PacketsTxInterface},"ErrorsTxInterface": %d{ErrorsTxInterface},"DiscardsTxInterface": %d{DiscardsTxInterface},"TotalBytesRx": %d{TotalBytesRx},"TotalBytesTx": %d{TotalBytesTx}}\n
```

Sample Response: 
```json
{"LogTimestamp":"Wed Jul 3 05:17:22 2019","Customer":"Safe March","SessionID":"8A64Qwj9zCkfYDGJVoUZ","SessionType":"ZPN_ASSISTANT_BROKER_CONTROL","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"19.20.3","Platform":"el7","ZEN":"US-NY-8179","Connector":"Seattle App Connector 1","ConnectorGroup":"Azure App Connectors","PrivateIP":"10.0.0.4","PublicIP":"0.0.0.0","Latitude":47,"Longitude":-122,"CountryCode":"","TimestampAuthentication":"2019-06-27T05:05:23.348Z","TimestampUnAuthentication":"","CPUUtilization":1,"MemUtilization":20,"ServiceCount":2,"InterfaceDefRoute":"eth0","DefRouteGW":"10.0.0.1","PrimaryDNSResolver":"168.63.129.16","HostStartTime":"1513229995","ConnectorStartTime":"1555920005","NumOfInterfaces":2,"BytesRxInterface":319831966346,"PacketsRxInterface":1617569938,"ErrorsRxInterface":0,"DiscardsRxInterface":0,"BytesTxInterface":192958782635,"PacketsTxInterface":1797471190,"ErrorsTxInterface":0,"DiscardsTxInterface":0,"TotalBytesRx":10902554,"TotalBytesTx":48931771}
```

### Audit Logs

Default port: _9016_

Vendor documentation: https://help.zscaler.com/zpa/about-audit-log-fields

Zscaler response format:  
```
{"ModifiedTime":%j{modifiedTime:iso8601},"CreationTime":%j{creationTime:iso8601},"ModifiedBy":%d{modifiedBy},"RequestID":%j{requestId},"SessionID":%j{sessionId},"AuditOldValue":%j{auditOldValue},"AuditNewValue":%j{auditNewValue},"AuditOperationType":%j{auditOperationType},"ObjectType":%j{objectType},"ObjectName":%j{objectName},"ObjectID":%d{objectId},"CustomerID":%d{customerId},"User":%j{modifiedByUser},"ClientAuditUpdate":%d{isClientAudit}}\n
```

Sample Response: 
```json
{"ModifiedTime":"2021-11-17T04:29:38.000Z","CreationTime":"2021-11-17T04:29:38.000Z","ModifiedBy":12345678901234567,"RequestID":"11111111-1111-1111-1111-111111111111","SessionID":"1idn23nlfm2q1txa5h3r4mep6","AuditOldValue":"","AuditNewValue":"{\"id\":\"72058340288495701\",\"name\":\"Some-Name\",\"domainOrIpAddress\":\"1.0.0.1\",\"description\":\"This is a description field\",\"enabled\":\"true\"}","AuditOperationType":"Create","ObjectType":"Server","ObjectName":"Some-Name","ObjectID":12345678901234567,"CustomerID":98765432109876543,"User":"zpaadmin@xxxxxxxxxxxxxxxxx.zpa-customer.com","ClientAuditUpdate":0}
```

### Browser Access Logs

Default port: _9017_

Vendor documentation: https://help.zscaler.com/zpa/about-browser-access-log-fields

Zscaler response format:  
```
{"LogTimestamp":%j{LogTimestamp:time},"ConnectionID":%j{ConnectionID},"Exporter":%j{Exporter},"TimestampRequestReceiveStart":%j{TimestampRequestReceiveStart:iso8601},"TimestampRequestReceiveHeaderFinish":%j{TimestampRequestReceiveHeaderFinish:iso8601},"TimestampRequestReceiveFinish":%j{TimestampRequestReceiveFinish:iso8601},"TimestampRequestTransmitStart":%j{TimestampRequestTransmitStart:iso8601},"TimestampRequestTransmitFinish":%j{TimestampRequestTransmitFinish:iso8601},"TimestampResponseReceiveStart":%j{TimestampResponseReceiveStart:iso8601},"TimestampResponseReceiveFinish":%j{TimestampResponseReceiveFinish:iso8601},"TimestampResponseTransmitStart":%j{TimestampResponseTransmitStart:iso8601},"TimestampResponseTransmitFinish":%j{TimestampResponseTransmitFinish:iso8601},"TotalTimeRequestReceive":%d{TotalTimeRequestReceive},"TotalTimeRequestTransmit":%d{TotalTimeRequestTransmit},"TotalTimeResponseReceive":%d{TotalTimeResponseReceive},"TotalTimeResponseTransmit":%d{TotalTimeResponseTransmit},"TotalTimeConnectionSetup":%d{TotalTimeConnectionSetup},"TotalTimeServerResponse":%d{TotalTimeServerResponse},"Method":%j{Method},"Protocol":%j{Protocol},"Host":%j{Host},"URL":%j{URL},"UserAgent":%j{UserAgent},"XFF":%j{XFF},"NameID":%j{NameID},"StatusCode":%d{StatusCode},"RequestSize":%d{RequestSize},"ResponseSize":%d{ResponseSize},"ApplicationPort":%d{ApplicationPort},"ClientPublicIp":%j{ClientPublicIp},"ClientPublicPort":%d{ClientPublicPort},"ClientPrivateIp":%j{ClientPrivateIp},"Customer":%j{Customer},"ConnectionStatus":%j{ConnectionStatus},"ConnectionReason":%j{ConnectionReason},"Origin":%j{Origin},"CorsToken":%j{CorsToken}}\n
```

Sample Response: 
```json
{"LogTimestamp":"Wed Jul 3 05:12:25 2019","ConnectionID":"","Exporter":"unset","TimestampRequestReceiveStart":"2019-07-03T05:12:25.723Z","TimestampRequestReceiveHeaderFinish":"2019-07-03T05:12:25.723Z","TimestampRequestReceiveFinish":"2019-07-03T05:12:25.723Z","TimestampRequestTransmitStart":"2019-07-03T05:12:25.790Z","TimestampRequestTransmitFinish":"2019-07-03T05:12:25.790Z","TimestampResponseReceiveStart":"2019-07-03T05:12:25.791Z","TimestampResponseReceiveFinish":"2019-07-03T05:12:25.791Z","TimestampResponseTransmitStart":"2019-07-03T05:12:25.791Z","TimestampResponseTransmitFinish":"2019-07-03T05:12:25.791Z","TotalTimeRequestReceive":127,"TotalTimeRequestTransmit":21,"TotalTimeResponseReceive":73,"TotalTimeResponseTransmit":13,"TotalTimeConnectionSetup":66995,"TotalTimeServerResponse":1349,"Method":"GET","Protocol":"HTTPS","Host":"portal.beta.zdemo.net","URL":"/media/Regular.woff","UserAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15","XFF":"","NameID":"admin@zdemo.net","StatusCode":304,"RequestSize":615,"ResponseSize":331,"ApplicationPort":443,"ClientPublicIp":"175.16.199.1","ClientPublicPort":60006,"ClientPrivateIp":"","Customer":"ANZ Team/zdemo in beta","ConnectionStatus":"","ConnectionReason":""}
```

### User Activity Logs

Default port: _9018_

Vendor documentation: https://help.zscaler.com/zpa/about-user-activity-log-fields

Zscaler response format:  
```
{"LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"SessionID": %j{SessionID},"ConnectionID": %j{ConnectionID},"InternalReason": %j{InternalReason},"ConnectionStatus": %j{ConnectionStatus},"IPProtocol": %d{IPProtocol},"DoubleEncryption": %d{DoubleEncryption},"Username": %j{Username},"ServicePort": %d{ServicePort},"ClientPublicIP": %j{ClientPublicIP},"ClientPrivateIP": %j{ClientPrivateIP},"ClientLatitude": %f{ClientLatitude},"ClientLongitude": %f{ClientLongitude},"ClientCountryCode": %j{ClientCountryCode},"ClientZEN": %j{ClientZEN},"Policy": %j{Policy},"Connector": %j{Connector},"ConnectorZEN": %j{ConnectorZEN},"ConnectorIP": %j{ConnectorIP},"ConnectorPort": %d{ConnectorPort},"Host": %j{Host},"Application": %j{Application},"AppGroup": %j{AppGroup},"Server": %j{Server},"ServerIP": %j{ServerIP},"ServerPort": %d{ServerPort},"PolicyProcessingTime": %d{PolicyProcessingTime},"ServerSetupTime": %d{ServerSetupTime},"TimestampConnectionStart": %j{TimestampConnectionStart:iso8601},"TimestampConnectionEnd": %j{TimestampConnectionEnd:iso8601},"TimestampCATx": %j{TimestampCATx:iso8601},"TimestampCARx": %j{TimestampCARx:iso8601},"TimestampAppLearnStart": %j{TimestampAppLearnStart:iso8601},"TimestampZENFirstRxClient": %j{TimestampZENFirstRxClient:iso8601},"TimestampZENFirstTxClient": %j{TimestampZENFirstTxClient:iso8601},"TimestampZENLastRxClient": %j{TimestampZENLastRxClient:iso8601},"TimestampZENLastTxClient": %j{TimestampZENLastTxClient:iso8601},"TimestampConnectorZENSetupComplete": %j{TimestampConnectorZENSetupComplete:iso8601},"TimestampZENFirstRxConnector": %j{TimestampZENFirstRxConnector:iso8601},"TimestampZENFirstTxConnector": %j{TimestampZENFirstTxConnector:iso8601},"TimestampZENLastRxConnector": %j{TimestampZENLastRxConnector:iso8601},"TimestampZENLastTxConnector": %j{TimestampZENLastTxConnector:iso8601},"ZENTotalBytesRxClient": %d{ZENTotalBytesRxClient},"ZENBytesRxClient": %d{ZENBytesRxClient},"ZENTotalBytesTxClient": %d{ZENTotalBytesTxClient},"ZENBytesTxClient": %d{ZENBytesTxClient},"ZENTotalBytesRxConnector": %d{ZENTotalBytesRxConnector},"ZENBytesRxConnector": %d{ZENBytesRxConnector},"ZENTotalBytesTxConnector": %d{ZENTotalBytesTxConnector},"ZENBytesTxConnector": %d{ZENBytesTxConnector},"Idp": %j{Idp},"ClientToClient": %j{c2c},"ConnectorZENSetupTime":%d{ConnectorZENSetupTime},"ConnectionSetupTime":%d{ConnectionSetupTime}}\n
```

Sample Response: 
```json
{"LogTimestamp": "Fri May 31 17:35:42 2019","Customer": "Customer XYZ","SessionID": "LHJdkjmNDf12nclBsvwA","ConnectionID": "SqyZIMkg0JTj7EABsvwA,Q+EjXGdrvbF2lPiBbedm","InternalReason": "","ConnectionStatus": "active","IPProtocol": 6,"DoubleEncryption": 0,"Username": "ZPA LSS Client","ServicePort": 10011,"ClientPublicIP": "81.2.69.193","ClientPrivateIP": "","ClientLatitude": 45.000000,"ClientLongitude": -119.000000,"ClientCountryCode": "US","ClientZEN": "broker2b.pdx","Policy": "ANZ Lab Apps","Connector": "ZDEMO ANZ","ConnectorZEN": "broker2b.pdx","ConnectorIP": "67.43.156.12","ConnectorPort": 60266,"Host": "175.16.199.1","Application": "ANZ Lab Apps","AppGroup": "ANZ Lab Apps","Server": "0","ServerIP": "175.16.199.1","ServerPort": 10011,"PolicyProcessingTime": 28,"CAProcessingTime": 1330,"ServerSetupTime": 465,"AppLearnTime": 0,"TimestampConnectionStart": "2019-05-30T08:20:42.230Z","TimestampConnectionEnd": "","TimestampCATx": "2019-05-30T08:20:42.230Z","TimestampCARx": "2019-05-30T08:20:42.231Z","TimestampAppLearnStart": "","TimestampZENFirstRxClient": "2019-05-30T08:20:42.424Z","TimestampZENFirstTxClient": "","TimestampZENLastRxClient": "2019-05-31T17:34:27.348Z","TimestampZENLastTxClient": "","TimestampConnectorZENSetupComplete": "2019-05-30T08:20:42.422Z","TimestampZENFirstRxConnector": "","TimestampZENFirstTxConnector": "2019-05-30T08:20:42.424Z","TimestampZENLastRxConnector": "","TimestampZENLastTxConnector": "2019-05-31T17:34:27.348Z","ZENTotalBytesRxClient": 2406926,"ZENBytesRxClient": 7115,"ZENTotalBytesTxClient": 0,"ZENBytesTxClient": 0,"ZENTotalBytesRxConnector": 0,"ZENBytesRxConnector": 0,"ZENTotalBytesTxConnector": 2406926,"ZENBytesTxConnector": 7115,"Idp": "Example IDP Config","ConnectorZENSetupTime":1640674274,"ConnectionSetupTime":1640675274}
```

**Note: In order to populate _Slowest Applications_ (visualization); _"ConnectorZENSetupTime"_ and _"ConnectionSetupTime"_ fields are added into the default response format of Zscaler User Activity Log above.**

### User Status Logs

Default port: _9019_

Vendor documentation: https://help.zscaler.com/zpa/about-user-status-log-fields

Zscaler response format:  
```
{"LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"Username": %j{Username},"SessionID": %j{SessionID},"SessionStatus": %j{SessionStatus},"Version": %j{Version},"ZEN": %j{ZEN},"CertificateCN": %j{CertificateCN},"PrivateIP": %j{PrivateIP},"PublicIP": %j{PublicIP},"Latitude": %f{Latitude},"Longitude": %f{Longitude},"CountryCode": %j{CountryCode},"TimestampAuthentication": %j{TimestampAuthentication:iso8601},"TimestampUnAuthentication": %j{TimestampUnAuthentication:iso8601},"TotalBytesRx": %d{TotalBytesRx},"TotalBytesTx": %d{TotalBytesTx},"Idp": %j{Idp},"Hostname": %j{Hostname},"Platform": %j{Platform},"ClientType": %j{ClientType},"TrustedNetworks": [%j(,){TrustedNetworks}],"TrustedNetworksNames": [%j(,){TrustedNetworksNames}],"SAMLAttributes": %j{SAMLAttributes},"PosturesHit": [%j(,){PosturesHit}],"PosturesMiss": [%j(,){PosturesMiss}],"ZENLatitude": %f{ZENLatitude},"ZENLongitude": %f{ZENLongitude},"ZENCountryCode": %j{ZENCountryCode},"FQDNRegistered": %j{fqdn_registered},"FQDNRegisteredError": %j{fqdn_register_error}}\n
```

Sample Response: 
```json
{"LogTimestamp":"Fri May 31 17:34:48 2019","Customer":"Customer XYZ","Username":"ZPA LSS Client","SessionID":"vkczUERSLl88Y+ytH8v5","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"19.12.0-36-g87dad18","ZEN":"broker2b.pdx","CertificateCN":"loggerz2x.pde.zpabeta.net","PrivateIP":"","PublicIP":"81.2.69.144","Latitude":45,"Longitude":-119,"CountryCode":"US","TimestampAuthentication":"2019-05-29T21:18:38.000Z","TimestampUnAuthentication":"","TotalBytesRx":31274866,"TotalBytesTx":25424152,"Idp":"IDP Config","Hostname":"DESKTOP-99HCSJ1","Platform":"windows","ClientType":"zpn_client_type_zapp","TrustedNetworks":"TN1_stc1","TrustedNetworksNames":"145248739466696953","SAMLAttributes":"myname:user,myemail:user@zscaler.com","PosturesHit":"sm-posture1,sm-posture2","PosturesMiss":"sm-posture11,sm-posture12","ZENLatitude":47,"ZENLongitude":-122,"ZENCountryCode":""}
```

## Fields and Sample Event

### App Connector Status Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.nat.ip | Translated IP of source based NAT sessions (e.g. internal client to internet). Typically connections traversing load balancers, firewalls, or routers. | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.cpu.usage | Percent CPU used which is normalized by the number of CPU cores and it ranges from 0 to 1. Scaling factor: 1000. For example: For a two core host, this value should be the average of the two cores, between 0 and 1. | scaled_float |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.location | Longitude and latitude | geo_point |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.version | Observer version. | keyword |
| organization.name | Organization name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
| zscaler_zpa.app_connector_status.connector.group | The App Connector group name. | keyword |
| zscaler_zpa.app_connector_status.connector.name | The App Connector name. | keyword |
| zscaler_zpa.app_connector_status.connector_start_time | Time in seconds at which App Connector was started. | date |
| zscaler_zpa.app_connector_status.connector_up_time | Time in seconds at which App Connector was started. | date |
| zscaler_zpa.app_connector_status.host_start_time | Time in seconds at which host was started. | date |
| zscaler_zpa.app_connector_status.host_up_time | Time in seconds at which host was started. | date |
| zscaler_zpa.app_connector_status.interface.name | The name of the interface to default route. | keyword |
| zscaler_zpa.app_connector_status.interface.received.bytes | The bytes received on the interface. | double |
| zscaler_zpa.app_connector_status.interface.received.discards | The discards received on the interface. | double |
| zscaler_zpa.app_connector_status.interface.received.errors | The errors received on the interface. | double |
| zscaler_zpa.app_connector_status.interface.received.packets | The packets received on the interface. | double |
| zscaler_zpa.app_connector_status.interface.transmitted.bytes | The bytes transmitted on the interface. | double |
| zscaler_zpa.app_connector_status.interface.transmitted.discards | The discards transmitted on the interface. | double |
| zscaler_zpa.app_connector_status.interface.transmitted.errors | The errors transmitted on the interface. | double |
| zscaler_zpa.app_connector_status.interface.transmitted.packets | The packets transmitted on the interface. | double |
| zscaler_zpa.app_connector_status.memory.utilization | The memory utilization in %. | double |
| zscaler_zpa.app_connector_status.num_of_interfaces | The number of interfaces on the App Connector host. | double |
| zscaler_zpa.app_connector_status.primary_dns_resolver | The IP address of the primary DNS resolver. | ip |
| zscaler_zpa.app_connector_status.private_ip | The private IP address of the App Connector. | ip |
| zscaler_zpa.app_connector_status.service.count | The number of services (combinations of domains/IP addresses and TCP/UDP ports) being monitored by the App Connector. | double |
| zscaler_zpa.app_connector_status.session.id | The TLS session ID. | keyword |
| zscaler_zpa.app_connector_status.session.status | The status of the session. | keyword |
| zscaler_zpa.app_connector_status.session.type | The type of session. | keyword |
| zscaler_zpa.app_connector_status.timestamp.authentication | Timestamp in microseconds when the App Connector was authenticated. | date |
| zscaler_zpa.app_connector_status.timestamp.unauthentication | Timestamp in microseconds when the App Connector was unauthenticated. | date |
| zscaler_zpa.app_connector_status.zen | The TLS session ID. | keyword |


An example event for `app_connector_status` looks as following:

```json
{
    "@timestamp": "2019-07-03T05:17:22.000Z",
    "agent": {
        "ephemeral_id": "5879b806-6298-48ab-89a6-19ddcf612162",
        "hostname": "docker-fleet-agent",
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "client": {
        "nat": {
            "ip": "10.0.0.1"
        }
    },
    "data_stream": {
        "dataset": "zscaler_zpa.app_connector_status",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "package",
        "dataset": "zscaler_zpa.app_connector_status",
        "ingested": "2022-02-03T13:30:46Z",
        "kind": "event",
        "original": "{\"LogTimestamp\":\"Wed Jul 3 05:17:22 2019\",\"Customer\":\"Customer Name\",\"SessionID\":\"8A64Qwj9zCkfYDGJVoUZ\",\"SessionType\":\"ZPN_ASSISTANT_BROKER_CONTROL\",\"SessionStatus\":\"ZPN_STATUS_AUTHENTICATED\",\"Version\":\"19.20.3\",\"Platform\":\"el7\",\"ZEN\":\"US-NY-8179\",\"Connector\":\"Some App Connector\",\"ConnectorGroup\":\"Some App Connector Group\",\"PrivateIP\":\"10.0.0.4\",\"PublicIP\":\"0.0.0.0\",\"Latitude\":47,\"Longitude\":-122,\"CountryCode\":\"\",\"TimestampAuthentication\":\"2019-06-27T05:05:23.348Z\",\"TimestampUnAuthentication\":\"\",\"CPUUtilization\":1,\"MemUtilization\":20,\"ServiceCount\":2,\"InterfaceDefRoute\":\"eth0\",\"DefRouteGW\":\"10.0.0.1\",\"PrimaryDNSResolver\":\"168.63.129.16\",\"HostStartTime\":\"1513229995\",\"HostUpTime\":\"1513229995\",\"ConnectorUpTime\":\"1555920005\",\"ConnectorStartTime\":\"1555920005\",\"NumOfInterfaces\":2,\"BytesRxInterface\":319831966346,\"PacketsRxInterface\":1617569938,\"ErrorsRxInterface\":0,\"DiscardsRxInterface\":0,\"BytesTxInterface\":192958782635,\"PacketsTxInterface\":1797471190,\"ErrorsTxInterface\":0,\"DiscardsTxInterface\":0,\"TotalBytesRx\":10902554,\"TotalBytesTx\":48931771}",
        "type": "info"
    },
    "host": {
        "cpu": {
            "usage": 1
        },
        "network": {
            "egress": {
                "bytes": 48931771
            },
            "ingress": {
                "bytes": 10902554
            }
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.7:33226"
        }
    },
    "observer": {
        "geo": {
            "location": {
                "lat": 47,
                "lon": -122
            }
        },
        "ip": [
            "0.0.0.0"
        ],
        "os": {
            "platform": "el7"
        },
        "type": "forwarder",
        "version": "19.20.3"
    },
    "organization": {
        "name": "Customer Name"
    },
    "related": {
        "ip": [
            "10.0.0.1",
            "0.0.0.0",
            "10.0.0.4",
            "168.63.129.16"
        ]
    },
    "tags": [
        "forwarded",
        "zscaler_zpa-app_connectors_status"
    ],
    "zscaler_zpa": {
        "app_connector_status": {
            "connector": {
                "group": "Some App Connector Group",
                "name": "Some App Connector"
            },
            "connector_start_time": "2019-04-22T08:00:05.000Z",
            "connector_up_time": "2019-04-22T08:00:05.000Z",
            "host_start_time": "2017-12-14T05:39:55.000Z",
            "host_up_time": "2017-12-14T05:39:55.000Z",
            "interface": {
                "name": "eth0",
                "received": {
                    "bytes": 319831966346,
                    "discards": 0,
                    "errors": 0,
                    "packets": 1617569938
                },
                "transmitted": {
                    "bytes": 192958782635,
                    "discards": 0,
                    "errors": 0,
                    "packets": 1797471190
                }
            },
            "memory": {
                "utilization": 20
            },
            "num_of_interfaces": 2,
            "primary_dns_resolver": "168.63.129.16",
            "private_ip": "10.0.0.4",
            "service": {
                "count": 2
            },
            "session": {
                "id": "8A64Qwj9zCkfYDGJVoUZ",
                "status": "ZPN_STATUS_AUTHENTICATED",
                "type": "ZPN_ASSISTANT_BROKER_CONTROL"
            },
            "timestamp": {
                "authentication": "2019-06-27T05:05:23.348Z"
            },
            "zen": "US-NY-8179"
        }
    }
}
```

## Audit Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| organization.id | Unique identifier for the organization. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.email | User email address. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.roles | Array of user roles at the time of the event. | keyword |
| x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | keyword |
| x509.not_after | Time at which the certificate is no longer considered valid. | date |
| x509.not_before | Time at which the certificate is first considered valid. | date |
| zscaler_zpa.audit.client_audit_update | The flag to represent if the event is a client Audit log. | long |
| zscaler_zpa.audit.object.id | The ID associated with the object name. | keyword |
| zscaler_zpa.audit.object.name | The name of the object. This corresponds to the Resource Name in the Audit Log page. | keyword |
| zscaler_zpa.audit.object.type | The location within the ZPA Admin Portal where the Action was performed. | keyword |
| zscaler_zpa.audit.operation_type | The type of action performed. | keyword |
| zscaler_zpa.audit.session.id | The ID for the administrator's session in the ZPA Admin Portal. This corresponds to a successful sign in action occurring. | keyword |
| zscaler_zpa.audit.value.new | The new value that was changed if the action type is create, sign in, or update. | flattened |
| zscaler_zpa.audit.value.old | The previous value that was changed if the action type is delete, sign out, or update. | flattened |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-17T04:29:38.000Z",
    "agent": {
        "ephemeral_id": "75bcfb32-c04c-4455-88ed-41a659043c80",
        "hostname": "docker-fleet-agent",
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "data_stream": {
        "dataset": "zscaler_zpa.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2021-11-17T04:29:38.000Z",
        "dataset": "zscaler_zpa.audit",
        "id": "11111111-1111-1111-1111-111111111111",
        "ingested": "2022-02-03T13:32:04Z",
        "kind": "event",
        "type": [
            "creation"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.7:54030"
        }
    },
    "organization": {
        "id": "98765432109876543"
    },
    "related": {
        "ip": [
            "1.0.0.1"
        ]
    },
    "server": {
        "address": "1.0.0.1",
        "ip": "1.0.0.1"
    },
    "tags": [
        "forwarded",
        "zscaler_zpa-audit"
    ],
    "user": {
        "id": "12345678901234567",
        "name": "zpaadmin@xxxxxxxxxxxxxxxxx.zpa-customer.com"
    },
    "zscaler_zpa": {
        "audit": {
            "client_audit_update": 0,
            "object": {
                "id": "12345678901234567",
                "name": "Some-Name",
                "type": "Server"
            },
            "operation_type": "Create",
            "session": {
                "id": "1idn23nlfm2q1txa5h3r4mep6"
            },
            "value": {
                "new": {
                    "description": "This is a description field",
                    "domainOrIpAddress": "1.0.0.1",
                    "enabled": "true",
                    "id": "72058340288495701",
                    "name": "Some-Name"
                }
            }
        }
    }
}
```

## Browser Access Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| organization.name | Organization name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.port | Port of the server. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |
| zscaler_zpa.browser_access.client_private_ip | The private IP address of the user's device. | ip |
| zscaler_zpa.browser_access.connection.id | The application connection ID. | keyword |
| zscaler_zpa.browser_access.connection.status | The status of the connection. | keyword |
| zscaler_zpa.browser_access.cors_token | The token from the CORS request. | keyword |
| zscaler_zpa.browser_access.exporter | The Browser Access Service instance to ZPA Public Service Edge or ZPA Private Service Edge instance. | keyword |
| zscaler_zpa.browser_access.origin | The Browser Access domain that led to the origination of the CORS request. | keyword |
| zscaler_zpa.browser_access.timestamp.request.receive.finish | Timestamp in microseconds when Browser Access Service received the last byte of the HTTP request from web browser. | date |
| zscaler_zpa.browser_access.timestamp.request.receive.header_finish | Timestamp in microseconds when Browser Access Service received the last byte of the HTTP header corresponding to the request from web browser. | date |
| zscaler_zpa.browser_access.timestamp.request.receive.start | Timestamp in microseconds when Browser Access Service received the first byte of the HTTP request from web browser. | date |
| zscaler_zpa.browser_access.timestamp.request.transmit.finish | Timestamp in microseconds when Browser Access Service sent the last byte of the HTTP request to the web server. | date |
| zscaler_zpa.browser_access.timestamp.request.transmit.start | Timestamp in microseconds when Browser Access Service sent the first byte of the HTTP request to the web server. | date |
| zscaler_zpa.browser_access.timestamp.response.receive.finish | Timestamp in microseconds when Browser Access Service received the last byte of the HTTP response from the web server. | date |
| zscaler_zpa.browser_access.timestamp.response.receive.start | Timestamp in microseconds when Browser Access Service received the first byte of the HTTP response from the web server. | date |
| zscaler_zpa.browser_access.timestamp.response.transmit.finish | Timestamp in microseconds when Browser Access Service sent the last byte of the HTTP response to the web browser. | date |
| zscaler_zpa.browser_access.timestamp.response.transmit.start | Timestamp in microseconds when Browser Access Service sent the first byte of the HTTP response to the web browser. | date |
| zscaler_zpa.browser_access.total_time.connection.setup | Time difference between reception of the first byte of the HTTP request from web browser and transmission of the first byte towards the web server, as seen by the Browser Access Service. | long |
| zscaler_zpa.browser_access.total_time.request.receive | Time difference between reception of the first and last byte of the HTTP request from the web browser as seen by the Browser Access Service. | long |
| zscaler_zpa.browser_access.total_time.request.transmit | Time difference between transmission of the first and last byte of the HTTP request towards the web server as seen by the Browser Access Service. | long |
| zscaler_zpa.browser_access.total_time.response.receive | Time difference between reception of the first and last byte of the HTTP response from the web server as seen by the Browser Access Service. | long |
| zscaler_zpa.browser_access.total_time.response.transmit | Time difference between transmission of the first and last byte of the HTTP request towards the web server as seen by the Browser Access Service. | long |
| zscaler_zpa.browser_access.total_time.server.response | Time difference between transmission of the last byte of the HTTP request towards the web server and reception of the first byte of the HTTP response from web server, as seen by the Browser Access Service. | long |
| zscaler_zpa.browser_access.xff | The X-Forwarded-For (XFF) HTTP header. | keyword |


An example event for `browser_access` looks as following:

```json
{
    "@timestamp": "2019-07-03T05:12:25.000Z",
    "agent": {
        "ephemeral_id": "10484a2f-b664-42ef-a849-7386c8257491",
        "hostname": "docker-fleet-agent",
        "id": "acf7dca8-817d-4681-bad3-1cc9bfefc49c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "client": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144",
        "port": 60006
    },
    "data_stream": {
        "dataset": "zscaler_zpa.browser_access",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "acf7dca8-817d-4681-bad3-1cc9bfefc49c",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network",
            "session"
        ],
        "dataset": "zscaler_zpa.browser_access",
        "ingested": "2022-02-14T07:28:10Z",
        "kind": "event",
        "type": "connection"
    },
    "http": {
        "request": {
            "body": {
                "bytes": 615
            },
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 331
            },
            "status_code": 304
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.26.0.7:47148"
        }
    },
    "organization": {
        "name": "ANZ Team/zdemo in beta"
    },
    "related": {
        "ip": [
            "81.2.69.144",
            "81.2.69.193"
        ]
    },
    "server": {
        "address": "portal.beta.zdemo.net",
        "port": 443
    },
    "tags": [
        "forwarded",
        "zscaler_zpa-browser_access"
    ],
    "url": {
        "domain": "portal.beta.zdemo.net",
        "extension": "woff",
        "original": "https://portal.beta.zdemo.net/media/regular.woff",
        "path": "/media/regular.woff",
        "scheme": "https"
    },
    "user": {
        "name": "admin@zdemo.net"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Safari",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15",
        "os": {
            "full": "Mac OS X 10.14.5",
            "name": "Mac OS X",
            "version": "10.14.5"
        },
        "version": "12.1.1"
    },
    "zscaler_zpa": {
        "browser_access": {
            "client_private_ip": "81.2.69.193",
            "exporter": "unset",
            "timestamp": {
                "request": {
                    "receive": {
                        "finish": "2019-07-03T05:12:25.723Z",
                        "header_finish": "2019-07-03T05:12:25.723Z",
                        "start": "2019-07-03T05:12:25.723Z"
                    },
                    "transmit": {
                        "finish": "2019-07-03T05:12:25.790Z",
                        "start": "2019-07-03T05:12:25.790Z"
                    }
                },
                "response": {
                    "receive": {
                        "finish": "2019-07-03T05:12:25.791Z",
                        "start": "2019-07-03T05:12:25.791Z"
                    },
                    "transmit": {
                        "finish": "2019-07-03T05:12:25.791Z",
                        "start": "2019-07-03T05:12:25.791Z"
                    }
                }
            },
            "total_time": {
                "connection": {
                    "setup": 66995
                },
                "request": {
                    "receive": 127,
                    "transmit": 21
                },
                "response": {
                    "receive": 73,
                    "transmit": 13
                },
                "server": {
                    "response": 1349
                }
            }
        }
    }
}
```

## User Activity Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| organization.name | Organization name. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| zscaler_zpa.user_activity.app_group | The application group name. | keyword |
| zscaler_zpa.user_activity.app_learn_time | Time in microseconds taken for App Connectors to learn about the requested application and report the learned information to the central authority. | long |
| zscaler_zpa.user_activity.application | The application name. | keyword |
| zscaler_zpa.user_activity.ca_processing_time | Time in microseconds taken for processing in the central authority. | long |
| zscaler_zpa.user_activity.client_private_ip | The private IP address of the Zscaler Client Connector. | ip |
| zscaler_zpa.user_activity.client_to_client | The status of the client-to-client connection. | keyword |
| zscaler_zpa.user_activity.connection.id | The application connection ID. | keyword |
| zscaler_zpa.user_activity.connection.setup_time | Time taken by the App Connector to process a notification from the App Connector selection microservice and set up the connection to the application server. | long |
| zscaler_zpa.user_activity.connection.status | The status of the connection. The expected values for this field are: [ Open, Close, Active ]. | keyword |
| zscaler_zpa.user_activity.connector.ip | The source IP address of the App Connector. | ip |
| zscaler_zpa.user_activity.connector.name | The App Connector name. | keyword |
| zscaler_zpa.user_activity.connector.port | The source port of the App Connector. | integer |
| zscaler_zpa.user_activity.connector_zen_setup_time | Time in microseconds taken for setting up connection between App Connector and ZPA Public Service Edge or ZPA Private Service Edge. | long |
| zscaler_zpa.user_activity.double_encryption | The double encryption status. | integer |
| zscaler_zpa.user_activity.idp | The name of the identity provider (IdP) as configured in the ZPA Admin Portal. | keyword |
| zscaler_zpa.user_activity.internal_reason | The internal reason for the status of the transaction. | keyword |
| zscaler_zpa.user_activity.policy.name | The access policy or timeout policy rule name. | keyword |
| zscaler_zpa.user_activity.policy.processing_time | Time in microseconds taken for processing the access policy associated with the application. | long |
| zscaler_zpa.user_activity.server | The server ID name. The server ID must be set to zero if dynamic server discovery is enabled. | keyword |
| zscaler_zpa.user_activity.server_setup_time | Time in microseconds taken for setting up connection at server. | long |
| zscaler_zpa.user_activity.service_port | The destination port of the server. | integer |
| zscaler_zpa.user_activity.session_id | The TLS session ID. | keyword |
| zscaler_zpa.user_activity.timestamp.app_learn_start | Time in microseconds taken for App Connectors to learn about the requested application and report the learned information to the central authority. | keyword |
| zscaler_zpa.user_activity.timestamp.ca.rx | Timestamp in microseconds when the central authority received request from ZPA Public Service Edge or ZPA Private Service Edge. | date |
| zscaler_zpa.user_activity.timestamp.ca.tx | Timestamp in microseconds when the central authority sent request to ZPA Public Service Edge or ZPA Private Service Edge. | date |
| zscaler_zpa.user_activity.timestamp.connection.end | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge terminated the connection. | date |
| zscaler_zpa.user_activity.timestamp.connection.start | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge received the initial request from Zscaler Client Connector to start the connection. | date |
| zscaler_zpa.user_activity.timestamp.connector_zen.setup_complete | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge received request from App Connector to set up data connection. The request from the App Connector is triggered by the initial request for a specific application from the Zscaler Client Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.client.rx.first | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge received the first byte from the Zscaler Client Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.client.rx.last | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge received the last byte from the Zscaler Client Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.client.tx.first | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge sent the first byte to the Zscaler Client Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.client.tx.last | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge sent the last byte to the Zscaler Client Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.connector.rx.first | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge received the first byte from the App Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.connector.rx.last | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge received the last byte from the App Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.connector.tx.first | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge sent the first byte to the App Connector. | date |
| zscaler_zpa.user_activity.timestamp.zen.connector.tx.last | Timestamp in microseconds when the ZPA Public Service Edge or ZPA Private Service Edge sent the last byte to the App Connector. | date |
| zscaler_zpa.user_activity.zen.client.bytes_rx | The additional bytes received from the Zscaler Client Connector since the last transaction log. | long |
| zscaler_zpa.user_activity.zen.client.bytes_tx | The additional bytes transmitted to the Zscaler Client Connector since the last transaction log. | long |
| zscaler_zpa.user_activity.zen.client.domain | The ZPA Public Service Edge (formerly Zscaler Enforcement Node or ZEN) or ZPA Private Service Edge that received the request from the Zscaler Client Connector. | keyword |
| zscaler_zpa.user_activity.zen.client.total.bytes_rx | The total bytes received from the Zscaler Client Connector by the ZPA Public Service Edge or ZPA Private Service Edge. | long |
| zscaler_zpa.user_activity.zen.client.total.bytes_tx | The total bytes transmitted to the Zscaler Client Connector from the ZPA Public Service Edge or ZPA Private Service Edge. | long |
| zscaler_zpa.user_activity.zen.connector.bytes_rx | The additional bytes received from the App Connector since the last transaction log. | long |
| zscaler_zpa.user_activity.zen.connector.bytes_tx | The additional bytes transmitted by the App Connector since the last transaction log. | long |
| zscaler_zpa.user_activity.zen.connector.domain | The ZPA Public Service Edge or ZPA Private Service Edge that sent the request from the App Connector. | keyword |
| zscaler_zpa.user_activity.zen.connector.total.bytes_rx | The total bytes received from the App Connector by the ZPA Public Service Edge or ZPA Private Service Edge. | long |
| zscaler_zpa.user_activity.zen.connector.total.bytes_tx | The total bytes transmitted to the App Connector from the ZPA Public Service Edge or ZPA Private Service Edge. | long |


An example event for `user_activity` looks as following:

```json
{
    "@timestamp": "2019-05-31T17:35:42.000Z",
    "agent": {
        "ephemeral_id": "2686f611-4bf3-4df9-8934-843cbd32d161",
        "hostname": "docker-fleet-agent",
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "client": {
        "geo": {
            "country_iso_code": "US",
            "location": {
                "lat": 45,
                "lon": -119
            }
        },
        "ip": "81.2.69.193"
    },
    "data_stream": {
        "dataset": "zscaler_zpa.user_activity",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "iam",
        "dataset": "zscaler_zpa.user_activity",
        "ingested": "2022-02-03T13:34:37Z",
        "kind": "event",
        "type": [
            "info",
            "user"
        ]
    },
    "host": {
        "ip": "175.16.199.1"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.7:59296"
        }
    },
    "network": {
        "type": "ipv6"
    },
    "organization": {
        "name": "Customer XYZ"
    },
    "related": {
        "hosts": [
            "broker2b.pdx"
        ],
        "ip": [
            "81.2.69.193",
            "175.16.199.1",
            "67.43.156.12"
        ]
    },
    "server": {
        "ip": "175.16.199.1",
        "port": 10011
    },
    "tags": [
        "forwarded",
        "zscaler_zpa-user_activity"
    ],
    "user": {
        "name": "ZPA LSS Client"
    },
    "zscaler_zpa": {
        "user_activity": {
            "app_group": "ABC Lab Apps",
            "app_learn_time": 0,
            "application": "ABC Lab Apps",
            "ca_processing_time": 1330,
            "client_to_client": "0",
            "connection": {
                "id": "SqyZIMkg0JTj7EABsvwA,Q+EjXGdrvbF2lPiBbedm",
                "setup_time": 192397,
                "status": "active"
            },
            "connector": {
                "ip": "67.43.156.12",
                "name": "ZDEMO ABC",
                "port": 60266
            },
            "connector_zen_setup_time": 191017,
            "double_encryption": 0,
            "idp": "Example IDP Config",
            "policy": {
                "name": "ABC Lab Apps",
                "processing_time": 28
            },
            "server": "0",
            "server_setup_time": 465,
            "service_port": 10011,
            "session_id": "LHJdkjmNDf12nclBsvwA",
            "timestamp": {
                "ca": {
                    "rx": "2019-05-30T08:20:42.231Z",
                    "tx": "2019-05-30T08:20:42.230Z"
                },
                "connection": {
                    "start": "2019-05-30T08:20:42.230Z"
                },
                "connector_zen": {
                    "setup_complete": "2019-05-30T08:20:42.422Z"
                },
                "zen": {
                    "client": {
                        "rx": {
                            "first": "2019-05-30T08:20:42.424Z",
                            "last": "2019-05-31T17:34:27.348Z"
                        }
                    },
                    "connector": {
                        "tx": {
                            "first": "2019-05-30T08:20:42.424Z",
                            "last": "2019-05-31T17:34:27.348Z"
                        }
                    }
                }
            },
            "zen": {
                "client": {
                    "bytes_rx": 7115,
                    "bytes_tx": 0,
                    "domain": "broker2b.pdx",
                    "total": {
                        "bytes_rx": 2406926,
                        "bytes_tx": 0
                    }
                },
                "connector": {
                    "bytes_rx": 0,
                    "bytes_tx": 7115,
                    "domain": "broker2b.pdx",
                    "total": {
                        "bytes_rx": 0,
                        "bytes_tx": 2406926
                    }
                }
            }
        }
    }
}
```

## User Status Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| organization.name | Organization name. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.geo.location | Longitude and latitude. | geo_point |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| zscaler_zpa.user_status.client.type | The client type for the request (i.e., Zscaler Client Connector, ZPA LSS, or Web Browser). | keyword |
| zscaler_zpa.user_status.fqdn.registered | The status of the hostname for the client-to-client connection. The expected values for this field are true or false. | boolean |
| zscaler_zpa.user_status.fqdn.registered_error | The status of the registered hostname. | keyword |
| zscaler_zpa.user_status.idp | The name of the identity provider (IdP) as configured in the ZPA Admin Portal. | keyword |
| zscaler_zpa.user_status.postures.hit | The posture profiles that the Zscaler Client Connector verified for this device. | keyword |
| zscaler_zpa.user_status.postures.miss | The posture profiles that the Zscaler Client Connector failed to verified for this device. | keyword |
| zscaler_zpa.user_status.private_ip | The private IP address of the Zscaler Client Connector. | ip |
| zscaler_zpa.user_status.saml_attributes | The list of SAML attributes reported by the IdP. | keyword |
| zscaler_zpa.user_status.session.id | The TLS session ID. | keyword |
| zscaler_zpa.user_status.session.status | The status of the session. | keyword |
| zscaler_zpa.user_status.timestamp.authentication | Timestamp in microseconds when the Zscaler Client Connector was authenticated. | date |
| zscaler_zpa.user_status.timestamp.unauthentication | Timestamp in microseconds when the Zscaler Client Connector was unauthenticated. | date |
| zscaler_zpa.user_status.total.bytes_rx | The total bytes received. | long |
| zscaler_zpa.user_status.total.bytes_tx | The total bytes transmitted. | long |
| zscaler_zpa.user_status.trusted_networks | The unique IDs for the trusted networks that the Zscaler Client Connector has determined for this device. | keyword |
| zscaler_zpa.user_status.trusted_networks_names | The names for the trusted networks that the Zscaler Client Connector has determined for this device. | keyword |
| zscaler_zpa.user_status.version | The Zscaler Client Connector version. | keyword |
| zscaler_zpa.user_status.zen.domain | The Public Service Edge (formerly Zscaler Enforcement Node or ZEN) or ZPA Private Service Edge that was selected for the connection | keyword |


An example event for `user_status` looks as following:

```json
{
    "@timestamp": "2019-05-31T17:34:48.000Z",
    "agent": {
        "ephemeral_id": "24dbe515-d3ac-4cb8-aa21-eeee2c2f9204",
        "hostname": "docker-fleet-agent",
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "client": {
        "geo": {
            "country_iso_code": "US",
            "location": {
                "lat": 45,
                "lon": -119
            }
        },
        "ip": "81.2.69.144"
    },
    "data_stream": {
        "dataset": "zscaler_zpa.user_status",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d03794ae-c5b7-46b2-8a63-42f00010ac23",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "iam",
        "dataset": "zscaler_zpa.user_status",
        "ingested": "2022-02-03T13:36:02Z",
        "kind": "state",
        "type": [
            "info",
            "user"
        ]
    },
    "host": {
        "hostname": "DESKTOP-99HCSJ1",
        "os": {
            "platform": "windows"
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.7:57146"
        }
    },
    "organization": {
        "name": "Customer XYZ"
    },
    "related": {
        "ip": [
            "81.2.69.144"
        ]
    },
    "server": {
        "geo": {
            "location": {
                "lat": 47,
                "lon": -122
            }
        }
    },
    "tags": [
        "forwarded",
        "zscaler_zpa-user_status"
    ],
    "user": {
        "name": "ZPA LSS Client"
    },
    "x509": {
        "issuer": {
            "common_name": "loggerz2x.pde.zpabeta.net"
        }
    },
    "zscaler_zpa": {
        "user_status": {
            "client": {
                "type": "zpn_client_type_zapp"
            },
            "fqdn": {
                "registered": false,
                "registered_error": "CUSTOMER_NOT_ENABLED"
            },
            "idp": "IDP Config",
            "postures": {
                "hit": [
                    "sm-posture1",
                    "sm-posture2"
                ],
                "miss": [
                    "sm-posture11",
                    "sm-posture12"
                ]
            },
            "saml_attributes": [
                "myname:user",
                "myemail:user@zscaler.com"
            ],
            "session": {
                "id": "vkczUERSLl88Y+ytH8v5",
                "status": "ZPN_STATUS_AUTHENTICATED"
            },
            "timestamp": {
                "authentication": "2019-05-29T21:18:38.000Z"
            },
            "total": {
                "bytes_rx": 31274866,
                "bytes_tx": 25424152
            },
            "trusted_networks": "TN1_stc1",
            "trusted_networks_names": "145248739466696953",
            "version": "19.12.0-36-g87dad18",
            "zen": {
                "domain": "broker2b.pdx"
            }
        }
    }
}
```
