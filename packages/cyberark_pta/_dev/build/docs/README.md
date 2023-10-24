# Cyberark Privileged Threat Analytics

CyberArk's Privileged Threat Analytics (PTA) continuously monitors the use of privileged accounts that are managed in the CyberArk Privileged Access Security (PAS) platform. This integration collects analytics from PTA's syslog via CEF-formatted logs.

### Configuration

Follow the steps described under [Send PTA syslog records to SIEM](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PTA/Outbound-Sending-%20PTA-syslog-Records-to-SIEM.htm) documentation to setup the integration:

- Sample syslog configuration for `systemparm.properties`:

```ini
[SYSLOG]
syslog_outbound=[{"siem": "Elastic", "format": "CEF", "host": "SIEM_MACHINE_ADDRESS", "port": 9301, "protocol": "TCP"}]
```

### Example event
An example event for pta looks as following:

```json
{
  "cef": {
    "device": {
      "event_class_id": "1",
      "product": "PTA",
      "vendor": "CyberArk",
      "version": "12.6"
    },
    "extensions": {
      "destinationAddress": "175.16.199.0",
      "destinationHostName": "dev1.domain.com",
      "destinationUserName": "andy@dev1.domain.com",
      "deviceCustomDate1": "2014-01-01T12:05:00.000Z",
      "deviceCustomDate1Label": "detectionDate",
      "deviceCustomString1": "None",
      "deviceCustomString1Label": "ExtraData",
      "deviceCustomString2": "52b06812ec3500ed864c461e",
      "deviceCustomString2Label": "EventID",
      "deviceCustomString3": "https://1.128.0.0/incidents/52b06812ec3500ed864c461e",
      "deviceCustomString3Label": "PTAlink",
      "deviceCustomString4": "https://myexternallink.com",
      "deviceCustomString4Label": "ExternalLink",
      "sourceAddress": "1.128.0.0",
      "sourceHostName": "prod1.domain.com",
      "sourceUserName": "mike2@prod1.domain.com"
    },
    "name": "Suspected credentials theft",
    "severity": "8",
    "version": "0"
  },
  "destination": {
    "domain": "dev1.domain.com",
    "ip": "175.16.199.0",
    "user": {
      "name": "andy@dev1.domain.com"
    }
  },
  "ecs": {
    "version": "8.3.0"
  },
  "event": {
    "code": "1",
    "created": [
      "2014-01-01T12:05:00.000Z"
    ],
    "id": [
      "52b06812ec3500ed864c461e"
    ],
    "ingested": "2022-07-28T14:05:49Z",
    "original": "CEF:0|CyberArk|PTA|12.6|1|Suspected credentials theft|8|suser=mike2@prod1.domain.com shost=prod1.domain.com src=1.128.0.0 duser=andy@dev1.domain.com dhost=dev1.domain.com dst=175.16.199.0 cs1Label=ExtraData cs1=None cs2Label=EventID cs2=52b06812ec3500ed864c461e deviceCustomDate1Label=detectionDate deviceCustomDate1=1388577900000 cs3Label=PTAlink cs3=https://1.128.0.0/incidents/52b06812ec3500ed864c461e cs4Label=ExternalLink cs4=https://myexternallink.com",
    "reference": [
      "https://1.128.0.0/incidents/52b06812ec3500ed864c461e"
    ],
    "severity": 8,
    "url": [
      "https://myexternallink.com"
    ]
  },
  "message": "Suspected credentials theft",
  "observer": {
    "product": "PTA",
    "vendor": "CyberArk",
    "version": "12.6"
  },
  "source": {
    "domain": "prod1.domain.com",
    "ip": "1.128.0.0",
    "user": {
      "name": "mike2@prod1.domain.com"
    }
  },
  "tags": [
    "cyberark_pta",
    "forwarded"
  ]
}
```

**Exported fields**

{{fields "events"}}