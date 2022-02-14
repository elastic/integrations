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

{{fields "app_connector_status"}}

{{event "app_connector_status"}}

## Audit Logs

{{fields "audit"}}

{{event "audit"}}

## Browser Access Logs

{{fields "browser_access"}}

{{event "browser_access"}}

## User Activity Logs

{{fields "user_activity"}}

{{event "user_activity"}}

## User Status Logs

{{fields "user_status"}}

{{event "user_status"}}
