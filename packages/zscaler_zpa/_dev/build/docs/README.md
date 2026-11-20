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
3. *Please make sure to use the latest version of given response formats.*

## ZPA Log Receiver Setup

For detailed docs on setting up the ZPA log receiver, refer to the Zscaler documentation at
- [About the Log Streaming Service](https://help.zscaler.com/zpa/about-log-streaming-service)
- [Configuring a Log Receiver](https://help.zscaler.com/zpa/configuring-log-receiver)

**Domain or IP**: Use the IP address/hostname of the Elastic Agent  
**TCP port**: Use the listening port of the Elastic Agent

With the default **Listen Address** of `localhost`, only an App Connector on the same host as the Elastic Agent can deliver logs. Set it to `0.0.0.0`, or to the address of a specific interface, to accept logs from other hosts.

Use one log receiver per log type, pointed at the listening port of the matching data stream. LSS can resend up to 15 minutes of logs after a connection outage, so duplicate records are possible.

### Log templates with `version` and `sourcetype` keys

Data streams whose response format starts with `version` and `sourcetype` keys have an advanced **Require Strict Field/Version Check** setting, which is off by default. When it is on, a record gets an `error.message` if its `version` or `sourcetype` is missing or doesn't match the data stream. Such records are still indexed.

## Compatibility

This package has been tested against `Zscaler Private Access Client Connector version 3.7.1.44`

## Documentation and configuration

### App Connector Status Logs

Default port: _9015_

Vendor documentation: https://help.zscaler.com/zpa/about-connector-status-log-fields

Zscaler App Connector Status response format (v2):  
```
{"LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"SessionID": %j{SessionID},"SessionType": %j{SessionType},"SessionStatus": %j{SessionStatus},"Version": %j{Version},"Platform": %j{Platform},"ZEN": %j{ZEN},"Connector": %j{Connector},"ConnectorGroup": %j{ConnectorGroup},"PrivateIP": %j{PrivateIP},"PublicIP": %j{PublicIP},"Latitude": %f{Latitude},"Longitude": %f{Longitude},"CountryCode": %j{CountryCode},"TimestampAuthentication": %j{TimestampAuthentication:iso8601},"TimestampUnAuthentication": %j{TimestampUnAuthentication:iso8601},"CPUUtilization": %d{CPUUtilization},"MemUtilization": %d{MemUtilization},"ServiceCount": %d{ServiceCount},"InterfaceDefRoute": %j{InterfaceDefRoute},"DefRouteGW": %j{DefRouteGW},"PrimaryDNSResolver": %j{PrimaryDNSResolver},"HostStartTime": %j{HostStartTime},"ConnectorStartTime": %j{ConnectorStartTime},"NumOfInterfaces": %d{NumOfInterfaces},"BytesRxInterface": %d{BytesRxInterface},"PacketsRxInterface": %d{PacketsRxInterface},"ErrorsRxInterface": %d{ErrorsRxInterface},"DiscardsRxInterface": %d{DiscardsRxInterface},"BytesTxInterface": %d{BytesTxInterface},"PacketsTxInterface": %d{PacketsTxInterface},"ErrorsTxInterface": %d{ErrorsTxInterface},"DiscardsTxInterface": %d{DiscardsTxInterface},"TotalBytesRx": %d{TotalBytesRx},"TotalBytesTx": %d{TotalBytesTx}}\n
```

Sample Response: 
```json
{"LogTimestamp":"Wed Jul 3 05:17:22 2019","Customer":"Safe March","SessionID":"8A64Qwj9zCkfYDGJVoUZ","SessionType":"ZPN_ASSISTANT_BROKER_CONTROL","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"19.20.3","Platform":"el7","ZEN":"US-NY-8179","Connector":"Seattle App Connector 1","ConnectorGroup":"Azure App Connectors","PrivateIP":"10.0.0.4","PublicIP":"0.0.0.0","Latitude":47,"Longitude":-122,"CountryCode":"","TimestampAuthentication":"2019-06-27T05:05:23.348Z","TimestampUnAuthentication":"","CPUUtilization":1,"MemUtilization":20,"ServiceCount":2,"InterfaceDefRoute":"eth0","DefRouteGW":"10.0.0.1","PrimaryDNSResolver":"168.63.129.16","HostStartTime":"1513229995","ConnectorStartTime":"1555920005","NumOfInterfaces":2,"BytesRxInterface":319831966346,"PacketsRxInterface":1617569938,"ErrorsRxInterface":0,"DiscardsRxInterface":0,"BytesTxInterface":192958782635,"PacketsTxInterface":1797471190,"ErrorsTxInterface":0,"DiscardsTxInterface":0,"TotalBytesRx":10902554,"TotalBytesTx":48931771}
```

### Audit Logs

Default port: _9016_

Vendor documentation: https://help.zscaler.com/zpa/about-audit-log-fields

Zscaler Audit response format (v1):  
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

Zscaler Browser Access response format (v1):  
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

Zscaler User Activity response format (v1):  
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

Zscaler User Status response format (v2):  
```
{"LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"Username": %j{Username},"SessionID": %j{SessionID},"SessionStatus": %j{SessionStatus},"Version": %j{Version},"ZEN": %j{ZEN},"CertificateCN": %j{CertificateCN},"PrivateIP": %j{PrivateIP},"PublicIP": %j{PublicIP},"Latitude": %f{Latitude},"Longitude": %f{Longitude},"CountryCode": %j{CountryCode},"TimestampAuthentication": %j{TimestampAuthentication:iso8601},"TimestampUnAuthentication": %j{TimestampUnAuthentication:iso8601},"TotalBytesRx": %d{TotalBytesRx},"TotalBytesTx": %d{TotalBytesTx},"Idp": %j{Idp},"Hostname": %j{Hostname},"Platform": %j{Platform},"ClientType": %j{ClientType},"TrustedNetworks": [%j(,){TrustedNetworks}],"TrustedNetworksNames": [%j(,){TrustedNetworksNames}],"SAMLAttributes": %j{SAMLAttributes},"PosturesHit": [%j(,){PosturesHit}],"PosturesMiss": [%j(,){PosturesMiss}],"ZENLatitude": %f{ZENLatitude},"ZENLongitude": %f{ZENLongitude},"ZENCountryCode": %j{ZENCountryCode},"FQDNRegistered": %j{FQDNRegistered},"FQDNRegisteredError": %j{FQDNRegisteredError}}\n
```

Sample Response: 
```json
{"LogTimestamp":"Fri May 31 17:34:48 2019","Customer":"Customer XYZ","Username":"ZPA LSS Client","SessionID":"vkczUERSLl88Y+ytH8v5","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"19.12.0-36-g87dad18","ZEN":"broker2b.pdx","CertificateCN":"loggerz2x.pde.zpabeta.net","PrivateIP":"","PublicIP":"81.2.69.144","Latitude":45,"Longitude":-119,"CountryCode":"US","TimestampAuthentication":"2019-05-29T21:18:38.000Z","TimestampUnAuthentication":"","TotalBytesRx":31274866,"TotalBytesTx":25424152,"Idp":"IDP Config","Hostname":"DESKTOP-99HCSJ1","Platform":"windows","ClientType":"zpn_client_type_zapp","TrustedNetworks":"TN1_stc1","TrustedNetworksNames":"145248739466696953","SAMLAttributes":"myname:user,myemail:user@zscaler.com","PosturesHit":"sm-posture1,sm-posture2","PosturesMiss":"sm-posture11,sm-posture12","ZENLatitude":47,"ZENLongitude":-122,"ZENCountryCode":""}
```

### AppProtection Logs

Default port: _9020_

Vendor documentation: https://help.zscaler.com/zpa/understanding-appprotection-log-fields

Zscaler AppProtection response format (v1):  
```
{"version":"v1","sourcetype":"zscaler_zpa.app_protection","LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"ConnectionID": %j{ConnectionID},"UserID": %j{UserID},"AssistantID": %j{AssistantID},"ExchangeSequenceIndex": %d{ExchangeSequenceIndex},"TimestampRequestReceiveStart": %d{TimestampRequestReceiveStart},"TimestampRequestReceiveHeaderFinish": %d{TimestampRequestReceiveHeaderFinish},"TimestampRequestReceiveFinish": %d{TimestampRequestReceiveFinish},"TimestampRequestTransmitStart": %d{TimestampRequestTransmitStart},"TimestampRequestTransmitFinish": %d{TimestampRequestTransmitFinish},"TimestampResponseReceiveStart": %d{TimestampResponseReceiveStart},"TimestampResponseReceiveFinish": %d{TimestampResponseReceiveFinish},"TimestampResponseTransmitStart": %d{TimestampResponseTransmitStart},"TimestampResponseTransmitFinish": %d{TimestampResponseTransmitFinish},"TotalTimeRequestReceive": %d{TotalTimeRequestReceive},"TotalTimeRequestTransmit": %d{TotalTimeRequestTransmit},"TotalTimeResponseReceive": %d{TotalTimeResponseReceive},"TotalTimeResponseTransmit": %d{TotalTimeResponseTransmit},"Domain": %j{Domain},"Method": %j{Method},"Protocol": %j{Protocol},"ProtocolVersion": %j{ProtocolVersion},"ContentType": %j{ContentType},"ContentEncoding": %j{ContentEncoding},"TransferEncoding": %j{TransferEncoding},"Host": %j{Host},"Destination": %j{Destination},"OriginDomain": %j{OriginDomain},"URL": %j{URL},"UserAgent": %j{UserAgent},"HTTPError": %j{HTTPError},"ClientPublicIp": %j{ClientPublicIp},"ClientPort": %d{ClientPort},"UpgradeHeaderPresent": %d{UpgradeHeaderPresent},"StatusCode": %d{StatusCode},"RequestHdrSize": %d{RequestHdrSize},"ResponseHdrSize": %d{ResponseHdrSize},"RequestBodySize": %d{RequestBodySize},"ResponseBodySize": %d{ResponseBodySize},"Application": %d{Application},"ApplicationGroup": %d{ApplicationGroup},"InspectionPolicy": %d{InspectionPolicy},"InspectionProfile": %d{InspectionProfile},"ParanoiaLevel": %d{ParanoiaLevel},"InspectionControlsHitCount": %d{InspectionControlsHitCount},"InspectionRuleProcessingTime": %d{InspectionRuleProcessingTime},"InspectionReqHeadersProcessingTime": %d{InspectionReqHeadersProcessingTime},"InspectionReqBodyProcessingTime": %d{InspectionReqBodyProcessingTime},"InspectionRespHeadersProcessingTime": %d{InspectionRespHeadersProcessingTime},"InspectionRespBodyProcessingTime": %d{InspectionRespBodyProcessingTime},"CertificateId": %d{CertificateId},"DoubleEncryption": %d{DoubleEncryption},"SSLInspection": %d{SSLInspection},"TotalBytesProcessed": %d{TotalBytesProcessed},"InspectionControls": [%j(,){InspectionControlArray}],"InspectionControlTypes": [%j(,){ControlTypeArray}],"InspectionControlCategories": [%j(,){InspectionControlCategories}],"Actions": [%j(,){Actions}],"Severities": [%j(,){SeveritiesArray}],"Descriptions": [%j(,){DescriptiveExplanationsArray}]}\n
```

Sample Response: 
```json
{"version":"v1","sourcetype":"zscaler_zpa.app_protection","LogTimestamp": "Mon Nov  2 15:32:26 2026","Customer": "Example Corp","ConnectionID": "q7Rk2LmXw9TfB4vNe1Hs,Zp3YdG8uKc+Wj0aQxE5n","UserID": "10000001","AssistantID": "Example Connector-1700000000001","ExchangeSequenceIndex": 0,"TimestampRequestReceiveStart": 1793633546400202,"TimestampRequestReceiveHeaderFinish": 1793633546400227,"TimestampRequestReceiveFinish": 1793633546401233,"TimestampRequestTransmitStart": 0,"TimestampRequestTransmitFinish": 0,"TimestampResponseReceiveStart": 1793633546404520,"TimestampResponseReceiveFinish": 1793633546404612,"TimestampResponseTransmitStart": 0,"TimestampResponseTransmitFinish": 1793633546404684,"TotalTimeRequestReceive": 0,"TotalTimeRequestTransmit": 0,"TotalTimeResponseReceive": 92,"TotalTimeResponseTransmit": 0,"Domain": "dvwa.example.com","Method": "GET","Protocol": "HTTP","ProtocolVersion": "1.1","ContentType": "","ContentEncoding": "","TransferEncoding": "","Host": "dvwa.example.com","Destination": "dvwa.example.com","OriginDomain": "","URL": "/","UserAgent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36","HTTPError": "success","ClientPublicIp": "203.0.113.11","ClientPort": 80,"UpgradeHeaderPresent": 0,"StatusCode": 302,"RequestHdrSize": 364,"ResponseHdrSize": 405,"RequestBodySize": 0,"ResponseBodySize": 0,"Application": 216172782113784001,"ApplicationGroup": 216172782113783942,"InspectionPolicy": 216172782113784010,"InspectionProfile": 216172782113784008,"ParanoiaLevel": 4,"InspectionControlsHitCount": 0,"InspectionRuleProcessingTime": 2798,"InspectionReqHeadersProcessingTime": 964,"InspectionReqBodyProcessingTime": 1758,"InspectionRespHeadersProcessingTime": 34,"InspectionRespBodyProcessingTime": 42,"CertificateId": 0,"DoubleEncryption": 0,"SSLInspection": 0,"TotalBytesProcessed": 0,"InspectionControls": [],"InspectionControlTypes": [],"InspectionControlCategories": [],"Actions": [],"Severities": [],"Descriptions": []}
```

**Note: AppProtection logs are only produced when the ZPA AppProtection add-on is in use. Records where AppProtection controls were hit are indexed with `event.kind: alert`. This data stream is enabled by default, so upgrading adds a listener on port 9020.**

### Microsegmentation Flow Logs

Default port: _9021_

Vendor documentation: https://help.zscaler.com/zpa/understanding-microsegmentation-flow-log-fields

Zscaler Microsegmentation Flow response format (v1):  
```
{"version":"v1","sourcetype":"zscaler_zpa.microsegmentation_flow","LogTimestamp": %j{LogTimestamp:time},"Customer": %j{Customer},"AgentID": %j{AgentID},"AgentName": %j{AgentName},"ResourceID": %j{ResourceID},"ResourceName": %j{ResourceName},"AppZoneID": %j{AppZoneID},"AppZoneName": %j{AppZoneName},"ConnectionStartTime": %j{ConnectionStartTime:iso8601},"SourceIP": %j{SourceIP},"DestinationIP": %j{DestinationIP},"SourcePorts": [%d(,){SourcePorts}],"DestinationPort": %d{DestinationPort},"Protocol": %d{Protocol},"AppName": [%j(,){AppName}],"AppExecutablePath": [%j(,){AppExecutablePath}],"Direction": %j{Direction},"PolicyID": %j{PolicyID},"PolicyName": %j{PolicyName},"EnforcementReason": %j{EnforcementReason},"EnforcementAction": %j{EnforcementAction},"EnforcementDisposition": %j{EnforcementDisposition}}\n
```

Sample Response: 
```json
{"version":"v1","sourcetype":"zscaler_zpa.microsegmentation_flow","LogTimestamp": "Mon Nov  2 15:40:18 2026","Customer": "Example Corp","AgentID": "71234567890123456-98032e15dee3d704713d9a8368a2c50f","AgentName": "srv-app-01.example.com-98032e15dee3d704713d9a8368a2c50f","ResourceID": "71234567890123456-8fe5a00c3ad21356fc301228968e970c","ResourceName": "srv-app-01.example.com","AppZoneID": "71234567890123456-6547eeb570535a78db73d4b2c59cdc01","AppZoneName": "example-zone-app","ConnectionStartTime": "2026-11-02T15:40:13.463Z","SourceIP": "192.0.2.10","DestinationIP": "192.0.2.20","SourcePorts": [45566,45568,45582,45584,45586],"DestinationPort": 1443,"Protocol": 6,"AppName": ["ncat"],"AppExecutablePath": ["/usr/bin/ncat"],"Direction": "OUTBOUND","PolicyID": "71234567890123456-b435222fdcaa2795a9ff0032c27e9181","PolicyName": "example_app_to_api_allow","EnforcementReason": "RULE","EnforcementAction": "ALLOW","EnforcementDisposition": "CONNECTED"}
```

**Note: Microsegmentation Flow logs are only produced when Zscaler Microsegmentation is provisioned for the tenant. This data stream is enabled by default, so upgrading adds a listener on port 9021.**

## Fields and Sample Event

### App Connector Status Logs

{{fields "app_connector_status"}}

{{event "app_connector_status"}}

### Audit Logs

{{fields "audit"}}

{{event "audit"}}

### Browser Access Logs

{{fields "browser_access"}}

{{event "browser_access"}}

### User Activity Logs

{{fields "user_activity"}}

{{event "user_activity"}}

### User Status Logs

{{fields "user_status"}}

{{event "user_status"}}

### AppProtection Logs

{{fields "app_protection"}}

{{event "app_protection"}}

### Microsegmentation Flow Logs

{{fields "microsegmentation_flow"}}

{{event "microsegmentation_flow"}}
