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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zpa.app_connector_status.connector.group | The App Connector group name. | keyword |
| zscaler_zpa.app_connector_status.connector.name | The App Connector name. | keyword |
| zscaler_zpa.app_connector_status.connector_start_time | Time in seconds at which App Connector was started. | date |
| zscaler_zpa.app_connector_status.host_start_time | Time in seconds at which host was started. | date |
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
        "ephemeral_id": "a668f81e-2848-4d79-95ef-1ecd5a6d332c",
        "id": "85fbad05-ff47-41ab-b16e-b299c3b10b39",
        "name": "elastic-agent-11095",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "nat": {
            "ip": "10.0.0.1"
        }
    },
    "data_stream": {
        "dataset": "zscaler_zpa.app_connector_status",
        "namespace": "67128",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "85fbad05-ff47-41ab-b16e-b299c3b10b39",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "package"
        ],
        "dataset": "zscaler_zpa.app_connector_status",
        "ingested": "2025-09-16T07:32:52Z",
        "kind": "event",
        "original": "{\"LogTimestamp\":\"Wed Jul 3 05:17:22 2019\",\"Customer\":\"Customer Name\",\"SessionID\":\"8A64Qwj9zCkfYDGJVoUZ\",\"SessionType\":\"ZPN_ASSISTANT_BROKER_CONTROL\",\"SessionStatus\":\"ZPN_STATUS_AUTHENTICATED\",\"Version\":\"19.20.3\",\"Platform\":\"el7\",\"ZEN\":\"US-NY-8179\",\"Connector\":\"Some App Connector\",\"ConnectorGroup\":\"Some App Connector Group\",\"PrivateIP\":\"10.0.0.4\",\"PublicIP\":\"0.0.0.0\",\"Latitude\":47,\"Longitude\":-122,\"CountryCode\":\"\",\"TimestampAuthentication\":\"2019-06-27T05:05:23.348Z\",\"TimestampUnAuthentication\":\"\",\"CPUUtilization\":1,\"MemUtilization\":20,\"ServiceCount\":2,\"InterfaceDefRoute\":\"eth0\",\"DefRouteGW\":\"10.0.0.1\",\"PrimaryDNSResolver\":\"168.63.129.16\",\"HostStartTime\":\"1513229995\",\"ConnectorStartTime\":\"1555920005\",\"NumOfInterfaces\":2,\"BytesRxInterface\":319831966346,\"PacketsRxInterface\":1617569938,\"ErrorsRxInterface\":0,\"DiscardsRxInterface\":0,\"BytesTxInterface\":192958782635,\"PacketsTxInterface\":1797471190,\"ErrorsTxInterface\":0,\"DiscardsTxInterface\":0,\"TotalBytesRx\":10902554,\"TotalBytesTx\":48931771}",
        "type": [
            "info"
        ]
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
            "address": "172.21.0.3:43448"
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
        "preserve_original_event",
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
            "host_start_time": "2017-12-14T05:39:55.000Z",
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

### Audit Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
        "ephemeral_id": "44b51929-01cc-40e0-9f61-1cd201dfb5f1",
        "id": "2a639f99-de36-4f57-92a5-c693d32d599d",
        "name": "elastic-agent-52871",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zpa.audit",
        "namespace": "69804",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2a639f99-de36-4f57-92a5-c693d32d599d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2021-11-17T04:29:38.000Z",
        "dataset": "zscaler_zpa.audit",
        "id": "11111111-1111-1111-1111-111111111111",
        "ingested": "2025-09-16T07:33:42Z",
        "kind": "event",
        "original": "{\"ModifiedTime\":\"2021-11-17T04:29:38.000Z\",\"CreationTime\":\"2021-11-17T04:29:38.000Z\",\"ModifiedBy\":12345678901234567,\"RequestID\":\"11111111-1111-1111-1111-111111111111\",\"SessionID\":\"1idn23nlfm2q1txa5h3r4mep6\",\"AuditOldValue\":\"\",\"AuditNewValue\":\"{\\\"id\\\":\\\"72058340288495701\\\",\\\"name\\\":\\\"Some-Name\\\",\\\"domainOrIpAddress\\\":\\\"1.0.0.1\\\",\\\"description\\\":\\\"This is a description field\\\",\\\"enabled\\\":\\\"true\\\"}\",\"AuditOperationType\":\"Create\",\"ObjectType\":\"Server\",\"ObjectName\":\"Some-Name\",\"ObjectID\":12345678901234567,\"CustomerID\":98765432109876543,\"User\":\"zpaadmin@xxxxxxxxxxxxxxxxx.zpa-customer.com\",\"ClientAuditUpdate\":0}",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.3:49510"
        }
    },
    "organization": {
        "id": "98765432109876543"
    },
    "related": {
        "ip": [
            "1.0.0.1"
        ],
        "user": [
            "12345678901234567",
            "zpaadmin",
            "zpaadmin@xxxxxxxxxxxxxxxxx.zpa-customer.com"
        ]
    },
    "server": {
        "address": "1.0.0.1",
        "ip": "1.0.0.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "zscaler_zpa-audit"
    ],
    "user": {
        "domain": "xxxxxxxxxxxxxxxxx.zpa-customer.com",
        "email": "zpaadmin@xxxxxxxxxxxxxxxxx.zpa-customer.com",
        "id": "12345678901234567",
        "name": "zpaadmin"
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

### Browser Access Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
        "ephemeral_id": "4f05f964-ac22-415a-b61a-751c5dd904dc",
        "id": "da5dbc19-3716-438a-84f1-667080bf03f1",
        "name": "elastic-agent-72091",
        "type": "filebeat",
        "version": "8.13.0"
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
        "namespace": "88779",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "da5dbc19-3716-438a-84f1-667080bf03f1",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network",
            "session"
        ],
        "dataset": "zscaler_zpa.browser_access",
        "ingested": "2025-09-16T07:34:33Z",
        "kind": "event",
        "original": "{\"LogTimestamp\":\"Wed Jul 3 05:12:25 2019\",\"ConnectionID\":\"\",\"Exporter\":\"unset\",\"TimestampRequestReceiveStart\":\"2019-07-03T05:12:25.723Z\",\"TimestampRequestReceiveHeaderFinish\":\"2019-07-03T05:12:25.723Z\",\"TimestampRequestReceiveFinish\":\"2019-07-03T05:12:25.723Z\",\"TimestampRequestTransmitStart\":\"2019-07-03T05:12:25.790Z\",\"TimestampRequestTransmitFinish\":\"2019-07-03T05:12:25.790Z\",\"TimestampResponseReceiveStart\":\"2019-07-03T05:12:25.791Z\",\"TimestampResponseReceiveFinish\":\"2019-07-03T05:12:25.791Z\",\"TimestampResponseTransmitStart\":\"2019-07-03T05:12:25.791Z\",\"TimestampResponseTransmitFinish\":\"2019-07-03T05:12:25.791Z\",\"TotalTimeRequestReceive\":127,\"TotalTimeRequestTransmit\":21,\"TotalTimeResponseReceive\":73,\"TotalTimeResponseTransmit\":13,\"TotalTimeConnectionSetup\":66995,\"TotalTimeServerResponse\":1349,\"Method\":\"GET\",\"Protocol\":\"HTTPS\",\"Host\":\"portal.beta.zdemo.net\",\"URL\":\"/media/Regular.woff\",\"UserAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15\",\"XFF\":\"\",\"NameID\":\"admin@zdemo.net\",\"StatusCode\":304,\"RequestSize\":615,\"ResponseSize\":331,\"ApplicationPort\":443,\"ClientPublicIp\":\"81.2.69.144\",\"ClientPublicPort\":60006,\"ClientPrivateIp\":\"81.2.69.193\",\"Customer\":\"ANZ Team/zdemo in beta\",\"ConnectionStatus\":\"\",\"ConnectionReason\":\"\"}",
        "type": [
            "connection"
        ]
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
            "address": "172.21.0.3:51684"
        }
    },
    "organization": {
        "name": "ANZ Team/zdemo in beta"
    },
    "related": {
        "ip": [
            "81.2.69.144",
            "81.2.69.193"
        ],
        "user": [
            "admin",
            "admin@zdemo.net"
        ]
    },
    "server": {
        "address": "portal.beta.zdemo.net",
        "port": 443
    },
    "tags": [
        "preserve_original_event",
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
        "domain": "zdemo.net",
        "email": "admin@zdemo.net",
        "name": "admin"
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

### User Activity Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
        "ephemeral_id": "6fb1a136-9af8-4d32-9dd8-c392ae6f2580",
        "id": "157c5fae-90f8-4fe0-8069-e93ccb609fe1",
        "name": "elastic-agent-97104",
        "type": "filebeat",
        "version": "8.13.0"
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
        "namespace": "25160",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "157c5fae-90f8-4fe0-8069-e93ccb609fe1",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "zscaler_zpa.user_activity",
        "ingested": "2025-09-16T07:35:23Z",
        "kind": "event",
        "original": "{\"LogTimestamp\": \"Fri May 31 17:35:42 2019\",\"Customer\": \"Customer XYZ\",\"SessionID\": \"LHJdkjmNDf12nclBsvwA\",\"ConnectionID\": \"SqyZIMkg0JTj7EABsvwA,Q+EjXGdrvbF2lPiBbedm\",\"InternalReason\": \"\",\"ConnectionStatus\": \"active\",\"IPProtocol\": 6,\"DoubleEncryption\": 0,\"Username\": \"ZPA LSS Client\",\"ServicePort\": 10011,\"ClientPublicIP\": \"81.2.69.193\",\"ClientLatitude\": 45.000000,\"ClientLongitude\": -119.000000,\"ClientCountryCode\": \"US\",\"ClientZEN\": \"broker2b.pdx\",\"Policy\": \"ABC Lab Apps\",\"Connector\": \"ZDEMO ABC\",\"ConnectorZEN\": \"broker2b.pdx\",\"ConnectorIP\": \"67.43.156.12\",\"ConnectorPort\": 60266,\"Host\": \"175.16.199.1\",\"Application\": \"ABC Lab Apps\",\"AppGroup\": \"ABC Lab Apps\",\"Server\": \"0\",\"ServerIP\": \"175.16.199.1\",\"ServerPort\": 10011,\"PolicyProcessingTime\": 28,\"CAProcessingTime\": 1330,\"ConnectorZENSetupTime\": 191017,\"ConnectionSetupTime\": 192397,\"ServerSetupTime\": 465,\"AppLearnTime\": 0,\"TimestampConnectionStart\": \"2019-05-30T08:20:42.230Z\",\"TimestampConnectionEnd\": \"\",\"TimestampCATx\": \"2019-05-30T08:20:42.230Z\",\"TimestampCARx\": \"2019-05-30T08:20:42.231Z\",\"TimestampAppLearnStart\": \"\",\"TimestampZENFirstRxClient\": \"2019-05-30T08:20:42.424Z\",\"TimestampZENFirstTxClient\": \"\",\"TimestampZENLastRxClient\": \"2019-05-31T17:34:27.348Z\",\"TimestampZENLastTxClient\": \"\",\"TimestampConnectorZENSetupComplete\": \"2019-05-30T08:20:42.422Z\",\"TimestampZENFirstRxConnector\": \"\",\"TimestampZENFirstTxConnector\": \"2019-05-30T08:20:42.424Z\",\"TimestampZENLastRxConnector\": \"\",\"TimestampZENLastTxConnector\": \"2019-05-31T17:34:27.348Z\",\"ZENTotalBytesRxClient\": 2406926,\"ZENBytesRxClient\": 7115,\"ZENTotalBytesTxClient\": 0,\"ZENBytesTxClient\": 0,\"ZENTotalBytesRxConnector\": 0,\"ZENBytesRxConnector\": 0,\"ZENTotalBytesTxConnector\": 2406926,\"ZENBytesTxConnector\": 7115,\"Idp\": \"Example IDP Config\",\"ClientToClient\": \"0\"}",
        "type": [
            "info",
            "user"
        ]
    },
    "host": {
        "ip": [
            "175.16.199.1"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.3:40418"
        }
    },
    "network": {
        "transport": "tcp"
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
        ],
        "user": [
            "ZPA LSS Client"
        ]
    },
    "server": {
        "ip": "175.16.199.1",
        "port": 10011
    },
    "tags": [
        "preserve_original_event",
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

### User Status Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
        "ephemeral_id": "1abe1ea0-4a67-4535-ac7c-c525e6248a65",
        "id": "080c4b8f-729b-46b0-b898-8c927e9d39a8",
        "name": "elastic-agent-82171",
        "type": "filebeat",
        "version": "8.13.0"
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
        "namespace": "13582",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "080c4b8f-729b-46b0-b898-8c927e9d39a8",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "zscaler_zpa.user_status",
        "ingested": "2025-09-16T07:36:12Z",
        "kind": "state",
        "original": "{\"LogTimestamp\":\"Fri May 31 17:34:48 2019\",\"Customer\":\"Customer XYZ\",\"Username\":\"ZPA LSS Client\",\"SessionID\":\"vkczUERSLl88Y+ytH8v5\",\"SessionStatus\":\"ZPN_STATUS_AUTHENTICATED\",\"Version\":\"19.12.0-36-g87dad18\",\"ZEN\":\"broker2b.pdx\",\"CertificateCN\":\"loggerz2x.pde.zpabeta.net\",\"PublicIP\":\"81.2.69.144\",\"Latitude\":45,\"Longitude\":-119,\"CountryCode\":\"US\",\"TimestampAuthentication\":\"2019-05-29T21:18:38.000Z\",\"TimestampUnAuthentication\":\"\",\"TotalBytesRx\":31274866,\"TotalBytesTx\":25424152,\"Idp\":\"IDP Config\",\"Hostname\":\"DESKTOP-99HCSJ1\",\"Platform\":\"windows\",\"ClientType\":\"zpn_client_type_zapp\",\"TrustedNetworks\":\"TN1_stc1\",\"TrustedNetworksNames\":\"145248739466696953\",\"SAMLAttributes\":\"myname:user,myemail:user@zscaler.com\",\"PosturesHit\":\"sm-posture1,sm-posture2\",\"PosturesMiss\":\"sm-posture11,sm-posture12\",\"ZENLatitude\":47,\"ZENLongitude\":-122,\"ZENCountryCode\":\"\",\"FQDNRegistered\": \"0\",\"FQDNRegisteredError\": \"CUSTOMER_NOT_ENABLED\"}",
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
            "address": "172.21.0.3:51342"
        }
    },
    "organization": {
        "name": "Customer XYZ"
    },
    "related": {
        "ip": [
            "81.2.69.144"
        ],
        "user": [
            "ZPA LSS Client"
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
        "preserve_original_event",
        "forwarded",
        "zscaler_zpa-user_status"
    ],
    "user": {
        "name": "ZPA LSS Client"
    },
    "x509": {
        "issuer": {
            "common_name": [
                "loggerz2x.pde.zpabeta.net"
            ]
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

### AppProtection Logs

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |
| input.type | Type of filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| log.source.address | Source address from which the log event was read / sent from. | keyword |  |
| zscaler_zpa.app_protection.actions | The action taken for each AppProtection control hit, index-aligned with `rule.id`. | keyword |  |
| zscaler_zpa.app_protection.application | The ID of the application. | keyword |  |
| zscaler_zpa.app_protection.application_group | The ID of the application group. | keyword |  |
| zscaler_zpa.app_protection.assistant_id | Documented by Zscaler as the App Connector ID, but the values seen are App Connector names. | keyword |  |
| zscaler_zpa.app_protection.certificate_id | The certificate ID. 0 means no certificate. | keyword |  |
| zscaler_zpa.app_protection.client_port | The port of the client, as reported. Observed values suggest it may be the server port. | long |  |
| zscaler_zpa.app_protection.connection_id | The application connection ID. Joins with `zscaler_zpa.user_activity.connection.id`. | keyword |  |
| zscaler_zpa.app_protection.content_encoding | The value of the content encoding within the HTTP header. | keyword |  |
| zscaler_zpa.app_protection.content_type | The content type. | keyword |  |
| zscaler_zpa.app_protection.double_encryption | Whether double encryption is on. | boolean |  |
| zscaler_zpa.app_protection.exchange_sequence_index | The HTTP exchange sequence index within the TCP connection. | long |  |
| zscaler_zpa.app_protection.http_error | The HTTP error. | keyword |  |
| zscaler_zpa.app_protection.inspection_control_types | The type of each AppProtection control hit, index-aligned with `rule.id`. | keyword |  |
| zscaler_zpa.app_protection.inspection_controls_hit_count | The number of AppProtection control hits. | long |  |
| zscaler_zpa.app_protection.inspection_policy | The ID of the AppProtection policy. | keyword |  |
| zscaler_zpa.app_protection.inspection_profile | The ID of the AppProtection profile. | keyword |  |
| zscaler_zpa.app_protection.inspection_req_body_processing_time | The time in microseconds taken for processing the AppProtection request body. | long | micros |
| zscaler_zpa.app_protection.inspection_req_headers_processing_time | The time in microseconds taken for processing the AppProtection request headers. | long | micros |
| zscaler_zpa.app_protection.inspection_resp_body_processing_time | The time in microseconds taken for processing the AppProtection response body. | long | micros |
| zscaler_zpa.app_protection.inspection_resp_headers_processing_time | The time in microseconds taken for processing the AppProtection response headers. | long | micros |
| zscaler_zpa.app_protection.inspection_rule_processing_time | The time in microseconds taken for processing the AppProtection rule. | long | micros |
| zscaler_zpa.app_protection.micro_tenant_id | The Microtenant ID. | keyword |  |
| zscaler_zpa.app_protection.origin_domain | The value of the origin header in the cross-origin HTTP header. | keyword |  |
| zscaler_zpa.app_protection.paranoia_level | The OWASP predefined paranoia level (1-4). | long |  |
| zscaler_zpa.app_protection.protocol | The protocol, as reported. Copied to `network.protocol` when it is a protocol name, or to `http.version` when it is an HTTP version and `ProtocolVersion` is empty. | keyword |  |
| zscaler_zpa.app_protection.request_hdr_size | The size of the request header. | long | byte |
| zscaler_zpa.app_protection.response_hdr_size | The size of the response header. | long | byte |
| zscaler_zpa.app_protection.severities | The severity of each AppProtection control hit, as reported, index-aligned with `rule.id`. | keyword |  |
| zscaler_zpa.app_protection.ssl_inspection | Whether the inspected HTTPS traffic was terminated. | boolean |  |
| zscaler_zpa.app_protection.timestamp_request_receive_finish | When the received request was finished. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_request_receive_header_finish | When the received request header was finished. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_request_receive_start | When the received request was started. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_request_transmit_finish | When the transmitted request was finished. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_request_transmit_start | When the transmitted request was started. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_response_receive_finish | When the received response was finished. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_response_receive_start | When the received response was started. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_response_transmit_finish | When the transmitted response was finished. | date_nanos |  |
| zscaler_zpa.app_protection.timestamp_response_transmit_start | When the transmitted response was started. | date_nanos |  |
| zscaler_zpa.app_protection.total_bytes_processed | The total bytes processed. | long | byte |
| zscaler_zpa.app_protection.total_time_request_receive | The total time taken in microseconds for the request to be received. | long | micros |
| zscaler_zpa.app_protection.total_time_request_transmit | The total time taken in microseconds for the request to be transmitted. | long | micros |
| zscaler_zpa.app_protection.total_time_response_receive | The total time taken in microseconds for the response to be received. | long | micros |
| zscaler_zpa.app_protection.total_time_response_transmit | The total time taken in microseconds for the response to be transmitted. | long | micros |
| zscaler_zpa.app_protection.transfer_encoding | The value of the transfer encoding within the HTTP header. | keyword |  |
| zscaler_zpa.app_protection.upgrade_header_present | Whether the upgrade header is present. | boolean |  |


An example event for `app_protection` looks as following:

```json
{
    "@timestamp": "2026-11-02T15:32:26.000Z",
    "agent": {
        "ephemeral_id": "879dfe66-8ca1-4210-bf58-029f95d8cf91",
        "id": "ea7af754-2cee-4f10-9d6b-fe8ad7502ce7",
        "name": "elastic-agent-65958",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "as": {
            "number": 64502,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Madrid",
            "continent_name": "Europe",
            "country_iso_code": "ES",
            "country_name": "Spain",
            "location": {
                "lat": 40.41639,
                "lon": -3.7025
            },
            "region_iso_code": "ES-M",
            "region_name": "Madrid"
        },
        "ip": "203.0.113.11"
    },
    "data_stream": {
        "dataset": "zscaler_zpa.app_protection",
        "namespace": "71296",
        "type": "logs"
    },
    "destination": {
        "address": "dvwa.example.com",
        "domain": "dvwa.example.com"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ea7af754-2cee-4f10-9d6b-fe8ad7502ce7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "zscaler_zpa.app_protection",
        "duration": 4482000,
        "end": "2026-11-02T15:32:26.404684Z",
        "ingested": "2026-11-18T11:43:03Z",
        "kind": "event",
        "original": "{\"version\":\"v1\",\"sourcetype\":\"zscaler_zpa.app_protection\",\"LogTimestamp\": \"Mon Nov  2 15:32:26 2026\",\"Customer\": \"Example Corp\",\"ConnectionID\": \"q7Rk2LmXw9TfB4vNe1Hs,Zp3YdG8uKc+Wj0aQxE5n\",\"UserID\": \"10000001\",\"AssistantID\": \"Example Connector-1700000000001\",\"ExchangeSequenceIndex\": 0,\"TimestampRequestReceiveStart\": 1793633546400202,\"TimestampRequestReceiveHeaderFinish\": 1793633546400227,\"TimestampRequestReceiveFinish\": 1793633546401233,\"TimestampRequestTransmitStart\": 0,\"TimestampRequestTransmitFinish\": 0,\"TimestampResponseReceiveStart\": 1793633546404520,\"TimestampResponseReceiveFinish\": 1793633546404612,\"TimestampResponseTransmitStart\": 0,\"TimestampResponseTransmitFinish\": 1793633546404684,\"TotalTimeRequestReceive\": 0,\"TotalTimeRequestTransmit\": 0,\"TotalTimeResponseReceive\": 92,\"TotalTimeResponseTransmit\": 0,\"Domain\": \"dvwa.example.com\",\"Method\": \"GET\",\"Protocol\": \"HTTP\",\"ProtocolVersion\": \"1.1\",\"ContentType\": \"\",\"ContentEncoding\": \"\",\"TransferEncoding\": \"\",\"Host\": \"dvwa.example.com\",\"Destination\": \"dvwa.example.com\",\"OriginDomain\": \"\",\"URL\": \"/\",\"UserAgent\": \"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\",\"HTTPError\": \"success\",\"ClientPublicIp\": \"203.0.113.11\",\"ClientPort\": 80,\"UpgradeHeaderPresent\": 0,\"StatusCode\": 302,\"RequestHdrSize\": 364,\"ResponseHdrSize\": 405,\"RequestBodySize\": 0,\"ResponseBodySize\": 0,\"Application\": 216172782113784001,\"ApplicationGroup\": 216172782113783942,\"InspectionPolicy\": 216172782113784010,\"InspectionProfile\": 216172782113784008,\"ParanoiaLevel\": 4,\"InspectionControlsHitCount\": 0,\"InspectionRuleProcessingTime\": 2798,\"InspectionReqHeadersProcessingTime\": 964,\"InspectionReqBodyProcessingTime\": 1758,\"InspectionRespHeadersProcessingTime\": 34,\"InspectionRespBodyProcessingTime\": 42,\"CertificateId\": 0,\"DoubleEncryption\": 0,\"SSLInspection\": 0,\"TotalBytesProcessed\": 0,\"InspectionControls\": [],\"InspectionControlTypes\": [],\"InspectionControlCategories\": [],\"Actions\": [],\"Severities\": [],\"Descriptions\": []}",
        "start": "2026-11-02T15:32:26.400202Z",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "body": {
                "bytes": 0
            },
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 0
            },
            "status_code": 302
        },
        "version": "1.1"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.16.6.3:56904"
        }
    },
    "network": {
        "protocol": "http"
    },
    "organization": {
        "name": "Example Corp"
    },
    "related": {
        "hosts": [
            "dvwa.example.com"
        ],
        "ip": [
            "203.0.113.11"
        ],
        "user": [
            "10000001"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "zscaler_zpa-app_protection"
    ],
    "url": {
        "domain": "dvwa.example.com",
        "original": "/",
        "path": "/"
    },
    "user": {
        "name": "10000001"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "126.0.0.0"
    },
    "zscaler_zpa": {
        "app_protection": {
            "application": "216172782113784001",
            "application_group": "216172782113783942",
            "assistant_id": "Example Connector-1700000000001",
            "certificate_id": "0",
            "client_port": 80,
            "connection_id": "q7Rk2LmXw9TfB4vNe1Hs,Zp3YdG8uKc+Wj0aQxE5n",
            "double_encryption": false,
            "exchange_sequence_index": 0,
            "http_error": "success",
            "inspection_controls_hit_count": 0,
            "inspection_policy": "216172782113784010",
            "inspection_profile": "216172782113784008",
            "inspection_req_body_processing_time": 1758,
            "inspection_req_headers_processing_time": 964,
            "inspection_resp_body_processing_time": 42,
            "inspection_resp_headers_processing_time": 34,
            "inspection_rule_processing_time": 2798,
            "paranoia_level": 4,
            "protocol": "HTTP",
            "request_hdr_size": 364,
            "response_hdr_size": 405,
            "ssl_inspection": false,
            "timestamp_request_receive_finish": "2026-11-02T15:32:26.401233Z",
            "timestamp_request_receive_header_finish": "2026-11-02T15:32:26.400227Z",
            "timestamp_request_receive_start": "2026-11-02T15:32:26.400202Z",
            "timestamp_response_receive_finish": "2026-11-02T15:32:26.404612Z",
            "timestamp_response_receive_start": "2026-11-02T15:32:26.404520Z",
            "timestamp_response_transmit_finish": "2026-11-02T15:32:26.404684Z",
            "total_bytes_processed": 0,
            "total_time_request_receive": 0,
            "total_time_request_transmit": 0,
            "total_time_response_receive": 92,
            "total_time_response_transmit": 0,
            "upgrade_header_present": false
        }
    }
}
```

### Microsegmentation Flow Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| zscaler_zpa.microsegmentation_flow.agent_id | The Microsegmentation agent ID. This is the Zscaler host agent, not the Elastic Agent. | keyword |
| zscaler_zpa.microsegmentation_flow.agent_name | The Microsegmentation agent name. | keyword |
| zscaler_zpa.microsegmentation_flow.app_zone_id | The ID of the AppZone the agent belongs to. | keyword |
| zscaler_zpa.microsegmentation_flow.app_zone_name | The name of the AppZone the agent belongs to. | keyword |
| zscaler_zpa.microsegmentation_flow.direction | The connection direction, kept only when it is not one of the values mapped to `network.direction` (`INBOUND`, `OUTBOUND` or `UNKNOWN`). | keyword |
| zscaler_zpa.microsegmentation_flow.enforcement_action | The policy enforcement action configured on the connection (`ALLOW`, `BLOCK` or `SIMBLOCK`, a simulated block). | keyword |
| zscaler_zpa.microsegmentation_flow.enforcement_disposition | The policy enforcement decision on the connection (`UNKNOWN`, `CONNECTED`, `REJECTED` or `DROPPED`). | keyword |
| zscaler_zpa.microsegmentation_flow.micro_tenant_id | The Microtenant ID. | keyword |
| zscaler_zpa.microsegmentation_flow.source_ports | The source ports of the aggregated connections between the same source, destination, protocol and destination port. | long |


An example event for `microsegmentation_flow` looks as following:

```json
{
    "@timestamp": "2026-11-02T15:40:18.000Z",
    "agent": {
        "ephemeral_id": "615bc3ab-4cca-4500-983f-41b5ad1654c7",
        "id": "e19566e9-c5e0-470e-b81b-b6fbe3e1dc1d",
        "name": "elastic-agent-39008",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "zscaler_zpa.microsegmentation_flow",
        "namespace": "57742",
        "type": "logs"
    },
    "destination": {
        "ip": "192.0.2.20",
        "port": 1443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e19566e9-c5e0-470e-b81b-b6fbe3e1dc1d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "allow",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "zscaler_zpa.microsegmentation_flow",
        "ingested": "2026-11-18T11:44:55Z",
        "kind": "event",
        "original": "{\"version\":\"v1\",\"sourcetype\":\"zscaler_zpa.microsegmentation_flow\",\"LogTimestamp\": \"Mon Nov  2 15:40:18 2026\",\"Customer\": \"Example Corp\",\"AgentID\": \"71234567890123456-98032e15dee3d704713d9a8368a2c50f\",\"AgentName\": \"srv-app-01.example.com-98032e15dee3d704713d9a8368a2c50f\",\"ResourceID\": \"71234567890123456-8fe5a00c3ad21356fc301228968e970c\",\"ResourceName\": \"srv-app-01.example.com\",\"AppZoneID\": \"71234567890123456-6547eeb570535a78db73d4b2c59cdc01\",\"AppZoneName\": \"example-zone-app\",\"ConnectionStartTime\": \"2026-11-02T15:40:13.463Z\",\"SourceIP\": \"192.0.2.10\",\"DestinationIP\": \"192.0.2.20\",\"SourcePorts\": [45566,45568,45582,45584,45586],\"DestinationPort\": 1443,\"Protocol\": 6,\"AppName\": [\"ncat\"],\"AppExecutablePath\": [\"/usr/bin/ncat\"],\"Direction\": \"OUTBOUND\",\"PolicyID\": \"71234567890123456-b435222fdcaa2795a9ff0032c27e9181\",\"PolicyName\": \"example_app_to_api_allow\",\"EnforcementReason\": \"RULE\",\"EnforcementAction\": \"ALLOW\",\"EnforcementDisposition\": \"CONNECTED\"}",
        "outcome": "success",
        "reason": "RULE",
        "start": "2026-11-02T15:40:13.463Z",
        "type": [
            "connection",
            "allowed"
        ]
    },
    "host": {
        "id": "71234567890123456-8fe5a00c3ad21356fc301228968e970c",
        "name": "srv-app-01.example.com"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.16.6.3:56016"
        }
    },
    "network": {
        "direction": "egress",
        "iana_number": "6",
        "transport": "tcp"
    },
    "organization": {
        "name": "Example Corp"
    },
    "process": {
        "executable": [
            "/usr/bin/ncat"
        ],
        "name": [
            "ncat"
        ]
    },
    "related": {
        "hosts": [
            "srv-app-01.example.com"
        ],
        "ip": [
            "192.0.2.10",
            "192.0.2.20"
        ]
    },
    "rule": {
        "id": "71234567890123456-b435222fdcaa2795a9ff0032c27e9181",
        "name": "example_app_to_api_allow"
    },
    "source": {
        "ip": "192.0.2.10"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "zscaler_zpa-microsegmentation_flow"
    ],
    "zscaler_zpa": {
        "microsegmentation_flow": {
            "agent_id": "71234567890123456-98032e15dee3d704713d9a8368a2c50f",
            "agent_name": "srv-app-01.example.com-98032e15dee3d704713d9a8368a2c50f",
            "app_zone_id": "71234567890123456-6547eeb570535a78db73d4b2c59cdc01",
            "app_zone_name": "example-zone-app",
            "enforcement_action": "ALLOW",
            "enforcement_disposition": "CONNECTED",
            "source_ports": [
                45566,
                45568,
                45582,
                45584,
                45586
            ]
        }
    }
}
```
