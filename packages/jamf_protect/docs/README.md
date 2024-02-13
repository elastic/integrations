# Jamf Protect

The Jamf Protect integration collects and parses data received from [Jamf Protect](https://learn.jamf.com/bundle/jamf-protect-documentation/page/About_Jamf_Protect.html) using a HTTP endpoint.

Use the Jamf Protect integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

## Data streams

The Jamf Protect integration collects one type of data stream: alerts, telemetry, and web threat events.

**Alerts** help you keep a record of Alerts and Unified Logs happening on endpoints using Jamf Protect.

**Telemetry** help you keep a record of audit events happening on endpoints using Jamf Protect.

**Web threat events** help you keep a record of web threat events happening on endpoints using Jamf Protect.

**Web traffic events** help you keep a record of content filtering and network requests happening on endpoints using Jamf Protect.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Protect (macOS Security) to send logs to the Elastic Agent (Custom HTTP Endpoint Logs)
    - Remote Alert Collection Endpoints
    - Unified Logs Collection Endpoints
    - Telemetry Collection Endpoints
- Configure Jamf Protect (Jamf Security Cloud) to send logs to the Elastic Agent (Custom HTTP Endpoint Logs)
    - Threat Event Stream 
    - Network Traffic Stream


### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs via HTTP Endpoint.

### Configure Jamf Protect

After validating settings, you can configure Jamf Protect to send events to Elastic.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Configure Threat Event Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)
- [Configure Network Traffic Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)

Then, depding on which events you want to send to Elastic, configure one or multiple HTTP endpoints:

**Remote Alert Collection Endpoints**:
- [ ] In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Unified Logs Collection Endpoints**:
- [ ] In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Telemetry Collection Endpoints**:
- [ ] In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Threats Event Stream**:
- [ ] In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Network Traffic Stream**:
- [ ] In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

## Logs reference

#### alerts

This is the `Alerts` dataset.

##### Example

An example event for `alerts` looks as following:

```json
{
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "User Elevated Action",
        "category": [
            "host",
            "process"
        ],
        "id": "7232d4a4-2289-49ba-a218-215ef3d62ec4",
        "kind": "alert",
        "module": "Alerts",
        "outcome": "success",
        "provider": "Jamf Protect",
        "reason": "Application used deprecated elevation API",
        "severity": 0,
        "start": "2023-11-01T12:20:38.851Z",
        "type": [
            "start"
        ]
    },
    "group": {
        "id": "0",
        "name": "wheel"
    },
    "host": {
        "hostname": "VMAC-2C23RW4DY",
        "id": "0000FE00-8406CE28ECFC4DAB",
        "ip": [
            "192.168.11.226"
        ],
        "os": {
            "family": "macos",
            "full": "Version 14.0 (Build 23A344)"
        }
    },
    "message": "{\"caid\":\"9344154b2323cbfdca098e408354212d4331ac3e9e538497aba0f766723661f7\",\"certid\":\"312301bd32f3fc8f82c7d6e57814764ae751f171f37496407d8998a32892bcea\",\"input\":{\"host\":{\"os\":\"Version 14.0 (Build 23A344)\",\"ips\":[\"192.168.11.226\"],\"serial\":\"Z2C23RW4DY\",\"hostname\":\"VMAC-2C23RW4DY\",\"protectVersion\":\"5.1.0.4\",\"provisioningUDID\":\"0000FE00-8406CE28ECFC4DAB\"},\"match\":{\"tags\":[\"MITREattack\",\"DefenseEvasion\",\"T1548.004\",\"AbuseElevationControlMechanism\",\"PrivilegeEscalation\"],\"uuid\":\"7232d4a4-2289-49ba-a218-215ef3d62ec4\",\"event\":{\"pid\":3136,\"type\":1,\"uuid\":\"e19385fc-6077-4d00-ad56-b89eec15e730\",\"subType\":7,\"timestamp\":1698841238.851668},\"facts\":[{\"name\":\"User Elevated Action\",\"tags\":[\"DefenseEvasion\",\"T1548.004\",\"PrivilegeEscalation\",\"MITREattack\",\"AbuseElevationControlMechanism\"],\"uuid\":\"db094865-99c2-416c-9f06-e7740d9e8a20\",\"human\":\"Application used deprecated elevation API\",\"actions\":[{\"name\":\"Report\"}],\"context\":[],\"version\":1,\"severity\":0}],\"custom\":false,\"actions\":[{\"name\":\"Report\"}],\"context\":[],\"severity\":0},\"related\":{\"files\":[],\"users\":[{\"uid\":0,\"name\":\"root\",\"uuid\":\"Z2C23RW4DY0\"},{\"uid\":501,\"name\":\"local-admin\",\"uuid\":\"Z2C23RW4DY1f5\"}],\"groups\":[{\"gid\":0,\"name\":\"wheel\",\"uuid\":\"Z2C23RW4DY0\"},{\"gid\":20,\"name\":\"staff\",\"uuid\":\"Z2C23RW4DY14\"}],\"binaries\":[{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":35273,\"path\":\"/usr/libexec/security_authtrampoline\",\"size\":134768,\"inode\":1152921500312504800,\"xattrs\":[],\"changed\":1694870910,\"created\":1694870910,\"sha1hex\":\"82e899cb1c8a42b74653b05ca526d5feae92b9f6\",\"accessed\":1694870910,\"modified\":1694870910,\"sha256hex\":\"7528368ce03bd25fb22520923f366e364ea40ae90b22dac79fba90f2152c3d32\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.apple.security_authtrampoline\",\"cdhash\":\"rbIoddPMz9MoMMZl1ATihY8wlMk=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false},{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":33261,\"path\":\"/Library/Application Support/JAMF/Remote Assist/jamfRemoteAssistLauncher\",\"size\":6929392,\"inode\":4631313,\"xattrs\":[],\"changed\":1698101729,\"created\":1697718684,\"sha1hex\":\"4f16310b5f518c8b0bd29afdfb8e2ca7a5a0b0b3\",\"accessed\":1698818094,\"modified\":1697718684,\"sha256hex\":\"b6e3e8d03cb0b11bf0e30649fcb3755e58babd00f942e07f85b656980fe4d9ff\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.jamf.remoteassist.launcher\",\"cdhash\":\"OkjDuX0cFaDreH32s6FfHKg1FqE=\",\"status\":0,\"teamid\":\"483DWKW443\",\"signerType\":2,\"authorities\":[\"Developer ID Application: JAMF Software (483DWKW443)\",\"Developer ID Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false},{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":35145,\"path\":\"/usr/bin/sudo\",\"size\":1446192,\"inode\":1152921500312502700,\"xattrs\":[],\"changed\":1694870910,\"created\":1694870910,\"sha1hex\":\"8e860430a91946640dcc5161c726a39dc8576cc3\",\"accessed\":1694870910,\"modified\":1694870910,\"sha256hex\":\"38e7f57d53e3c8847ea3361085e13d87849b31f588bfe9e9e1c02abfac542aef\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.apple.sudo\",\"cdhash\":\"LZl8hBA1BePrgPrqw+Ap/HR6YUg=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false},{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":33133,\"path\":\"/bin/bash\",\"size\":1310224,\"inode\":1152921500312501200,\"xattrs\":[],\"changed\":1694870910,\"created\":1694870910,\"sha1hex\":\"db9d08f69e6bff5c31ff7d7a0da06a0a8311c393\",\"accessed\":1694870910,\"modified\":1694870910,\"sha256hex\":\"4c70b5307a375045d205dbff19dc96fdaa25a77061446259204657c97726c70a\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.apple.bash\",\"cdhash\":\"w8D5iqHkJJxjGQGuFQLtfzG2Wes=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false},{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":33261,\"path\":\"/bin/zsh\",\"size\":1377584,\"inode\":1152921500312501200,\"xattrs\":[],\"changed\":1694870910,\"created\":1694870910,\"sha1hex\":\"959ade1e4967a51eb8757d723d5040090fdfcb5c\",\"accessed\":1694870910,\"modified\":1694870910,\"sha256hex\":\"ccb1ba009baa2353c3806fe4f56349497b542104b5104e7a82b8f8ce2304ec03\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.apple.zsh\",\"cdhash\":\"f8w59TUpUrUhesGyuRBvXldP3Q0=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false},{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":35181,\"path\":\"/usr/bin/login\",\"size\":172032,\"inode\":1152921500312502100,\"xattrs\":[],\"changed\":1694870910,\"created\":1694870910,\"sha1hex\":\"875c999ee4df1a16d7654636714f852f55d1cc57\",\"accessed\":1694870910,\"modified\":1694870910,\"sha256hex\":\"4fa5b402145c8228454641e232d3d4b4152df143bf3ffda98d75c200e661baf4\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.apple.login\",\"cdhash\":\"MnR8eKbXO4v5eUokTXLWEDUfCVY=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[\"com.apple.private.endpoint-security.submit.login\",\"com.apple.private.security.clear-library-validation\"],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false},{\"gid\":0,\"uid\":0,\"fsid\":16777230,\"mode\":33261,\"path\":\"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal\",\"size\":2222656,\"inode\":1152921500311913100,\"xattrs\":[],\"changed\":1694870910,\"created\":1694870910,\"sha1hex\":\"14c2df1ea5a91fed7527fcfdff74268e19524eb3\",\"accessed\":1694870910,\"modified\":1694870910,\"sha256hex\":\"17a6a338efd6052c871a6da90b81c483a3edea43c056326587735b89feaf189c\",\"isDownload\":false,\"objectType\":\"GPSystemObject\",\"isAppBundle\":false,\"isDirectory\":false,\"signingInfo\":{\"appid\":\"com.apple.Terminal\",\"cdhash\":\"wW5ML2vzWxs1MRJgpzVfrYJJ/GU=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"isScreenShot\":false}],\"processes\":[{\"gid\":0,\"pid\":3136,\"tty\":\"/dev/ttys016\",\"uid\":0,\"args\":[\"/usr/libexec/security_authtrampoline\",\"/Library/Application Support/JAMF/Remote Assist/Wipe\",\"auth 16\"],\"name\":\"security_authtrampoline\",\"path\":\"/usr/libexec/security_authtrampoline\",\"pgid\":3096,\"ppid\":3099,\"rgid\":0,\"ruid\":0,\"uuid\":\"c821d617-2ce5-4475-aae6-c428a1ad9e8c\",\"flags\":[],\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.apple.security_authtrampoline\",\"cdhash\":\"rbIoddPMz9MoMMZl1ATihY8wlMk=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698841238,\"originalParentPID\":3099,\"processIdentifier\":6750},{\"gid\":0,\"pid\":3099,\"tty\":\"/dev/ttys016\",\"uid\":0,\"args\":[\"/Library/Application Support/JAMF/Remote Assist/jamfRemoteAssistLauncher\",\"/operation=connector.uninstall\"],\"name\":\"jamfRemoteAssistLauncher\",\"path\":\"/Library/Application Support/JAMF/Remote Assist/jamfRemoteAssistLauncher\",\"pgid\":3096,\"ppid\":3098,\"rgid\":0,\"ruid\":0,\"uuid\":\"a382cfda-8964-4388-8c19-49d4eaef2ae7\",\"flags\":[],\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.jamf.remoteassist.launcher\",\"cdhash\":\"OkjDuX0cFaDreH32s6FfHKg1FqE=\",\"status\":0,\"teamid\":\"483DWKW443\",\"signerType\":2,\"authorities\":[\"Developer ID Application: JAMF Software (483DWKW443)\",\"Developer ID Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698841236,\"originalParentPID\":3098,\"processIdentifier\":6654},{\"gid\":20,\"pid\":3098,\"tty\":\"/dev/ttys016\",\"uid\":0,\"args\":[\"sudo\",\"/Library/Application Support/JAMF/Remote Assist/jamfRemoteAssistLauncher\",\"/operation=connector.uninstall\"],\"name\":\"sudo\",\"path\":\"/usr/bin/sudo\",\"pgid\":3096,\"ppid\":3096,\"rgid\":20,\"ruid\":501,\"uuid\":\"31060be9-a210-4e18-bec5-2b0b6c482563\",\"flags\":[],\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.apple.sudo\",\"cdhash\":\"LZl8hBA1BePrgPrqw+Ap/HR6YUg=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698841234,\"originalParentPID\":3096,\"processIdentifier\":6652},{\"gid\":20,\"pid\":3096,\"tty\":\"/dev/ttys016\",\"uid\":501,\"args\":[\"/bin/sh\",\"/Library/Application Support/JAMF/Remote Assist/Uninstall\"],\"name\":\"bash\",\"path\":\"/bin/bash\",\"pgid\":3096,\"ppid\":3063,\"rgid\":20,\"ruid\":501,\"uuid\":\"6600050c-406a-4cd6-8c31-1eefe04fea65\",\"flags\":[],\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.apple.bash\",\"cdhash\":\"w8D5iqHkJJxjGQGuFQLtfzG2Wes=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698841233,\"originalParentPID\":3063,\"processIdentifier\":6650},{\"gid\":20,\"pid\":3063,\"uid\":501,\"args\":[\"-zsh\"],\"name\":\"zsh\",\"path\":\"/bin/zsh\",\"pgid\":3063,\"ppid\":3062,\"rgid\":20,\"ruid\":501,\"uuid\":\"f596588c-0db5-4fdb-bd64-95584398c596\",\"flags\":[],\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.apple.zsh\",\"cdhash\":\"f8w59TUpUrUhesGyuRBvXldP3Q0=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698841233,\"originalParentPID\":3062,\"processIdentifier\":6608},{\"gid\":20,\"pid\":3062,\"uid\":0,\"args\":[\"login\",\"-pf\",\"local-admin\"],\"name\":\"login\",\"path\":\"/usr/bin/login\",\"pgid\":3062,\"ppid\":765,\"rgid\":20,\"ruid\":501,\"uuid\":\"bfd4dcd0-5054-4cab-9b8f-1e650d977771\",\"flags\":[],\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.apple.login\",\"cdhash\":\"MnR8eKbXO4v5eUokTXLWEDUfCVY=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[\"com.apple.private.endpoint-security.submit.login\",\"com.apple.private.security.clear-library-validation\"],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698841233,\"originalParentPID\":765,\"processIdentifier\":6606},{\"gid\":20,\"pid\":765,\"uid\":501,\"args\":[\"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal\"],\"name\":\"Terminal\",\"path\":\"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal\",\"pgid\":765,\"ppid\":1,\"rgid\":20,\"ruid\":501,\"uuid\":\"7fb1cc18-b1a9-467a-880a-3a6e86960880\",\"flags\":[],\"appPath\":\"/System/Applications/Utilities/Terminal.app\",\"processType\":\"GPSystemObject\",\"signingInfo\":{\"appid\":\"com.apple.Terminal\",\"cdhash\":\"wW5ML2vzWxs1MRJgpzVfrYJJ/GU=\",\"status\":0,\"teamid\":\"\",\"signerType\":0,\"authorities\":[\"Software Signing\",\"Apple Code Signing Certification Authority\",\"Apple Root CA\"],\"entitlements\":[],\"statusMessage\":\"No error.\",\"informationStage\":\"extended\"},\"inheritedFlags\":[],\"responsiblePID\":765,\"startTimestamp\":1698840671,\"originalParentPID\":1,\"processIdentifier\":1812}]},\"eventType\":\"GPProcessEvent\"}}",
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "process": {
        "args": [
            "/usr/libexec/security_authtrampoline",
            "/Library/Application Support/JAMF/Remote Assist/Wipe",
            "auth 16"
        ],
        "code_signature": {
            "signing_id": "com.apple.security_authtrampoline",
            "status": "No error.",
            "team_id": ""
        },
        "entity_id": "c821d617-2ce5-4475-aae6-c428a1ad9e8c",
        "executable": "/usr/libexec/security_authtrampoline",
        "group_leader": {
            "executable": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            "name": "Terminal",
            "pid": 765,
            "real_group": {
                "id": "20"
            },
            "real_user": {
                "id": "501"
            },
            "start": "2023-11-01T12:11:11Z",
            "user": {
                "id": "501"
            }
        },
        "hash": {
            "sha1": "82e899cb1c8a42b74653b05ca526d5feae92b9f6",
            "sha256": "7528368ce03bd25fb22520923f366e364ea40ae90b22dac79fba90f2152c3d32"
        },
        "name": "security_authtrampoline",
        "parent": {
            "code_signature": {
                "signing_id": "com.jamf.remoteassist.launcher",
                "status": "No error.",
                "team_id": "483DWKW443"
            },
            "executable": "/Library/Application Support/JAMF/Remote Assist/jamfRemoteAssistLauncher",
            "name": "jamfRemoteAssistLauncher",
            "pid": 3099,
            "real_group": {
                "id": "0"
            },
            "real_user": {
                "id": "0"
            },
            "start": "2023-11-01T12:20:36Z",
            "user": {
                "id": "0"
            }
        },
        "pid": 3136,
        "real_group": {
            "id": "0"
        },
        "real_user": {
            "id": "0"
        },
        "start": "2023-11-01T12:20:38Z",
        "tty": "/dev/ttys016",
        "user": {
            "id": "0"
        }
    },
    "related": {
        "hash": [
            "82e899cb1c8a42b74653b05ca526d5feae92b9f6",
            "7528368ce03bd25fb22520923f366e364ea40ae90b22dac79fba90f2152c3d32"
        ],
        "user": [
            "root",
            "local-admin",
            ""
        ]
    },
    "tags": [
        "DefenseEvasion",
        "T1548.004",
        "PrivilegeEscalation",
        "MITREattack",
        "AbuseElevationControlMechanism"
    ],
    "threat": {
        "framework": "MITRE ATT\u0026CK",
        "software": {
            "platforms": "macOS"
        }
    }
}
```

#### telemetry

This is the `Telemetry` dataset.

##### Example

An example event for `telemetry` looks as following:

```json
{
    "@timestamp": "2019-10-02T16:17:08.000Z",
    "agent": {
        "ephemeral_id": "d5ffc842-05cf-43da-96fe-905f95ab2e41",
        "id": "4f9748a6-cc5b-4160-bfdb-b533f9ba576a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.0"
    },
    "data_stream": {
        "dataset": "jamf_protect_telemetry.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "4f9748a6-cc5b-4160-bfdb-b533f9ba576a",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "action": "preference_list_event",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "jamf_protect_telemetry.log",
        "ingested": "2022-11-04T11:01:45Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "macbook_pro",
        "id": "X03XX889XXX3",
        "mac": [
            "38-F9-E8-15-5A-82"
        ],
        "os": {
            "type": "macos",
            "version": "Version 10.14.6 (Build 18G95)"
        }
    },
    "input": {
        "type": "tcp"
    },
    "jamf_protect_telemetry": {
        "log": {
            "dataset": "event",
            "event_attributes": {
                "audit_event": {
                    "excluded_processes": [
                        "/usr/bin/log",
                        "/usr/sbin/syslogd"
                    ],
                    "excluded_users": [
                        "_spotlight",
                        "_windowserver"
                    ]
                },
                "audit_event_log_verbose_messages": "1",
                "audit_level": 3,
                "file_event": {
                    "exclusion_paths": [
                        "/Users/.*/Library/.*"
                    ],
                    "inclusion_paths": [
                        "/Users/.*"
                    ],
                    "use_fuzzy_match": 0
                },
                "file_license_info": {
                    "license_expiration_date": "2020-01-01T00:00:00.000Z",
                    "license_key": "43cafc3da47e792939ea82c70...",
                    "license_type": "Annual",
                    "license_version": "1"
                },
                "log": {
                    "file": {
                        "location": "/var/log/JamfComplianceReporter.log",
                        "max_number_backups": 10,
                        "max_size_mega_bytes": 10,
                        "ownership": "root:wheel",
                        "permission": "640"
                    },
                    "remote_endpoint_enabled": 1,
                    "remote_endpoint_type": "AWSKinesis",
                    "remote_endpoint_type_awskinesis": {
                        "access_key_id": "AKIAQFE...",
                        "region": "us-east-1",
                        "secret_key": "JAdcoRIo4zsPz...",
                        "stream_name": "compliancereporter_testing"
                    }
                },
                "unified_log_predicates": [
                    "'(subsystem == \"com.example.networkstatistics\")'",
                    "'(subsystem == \"com.apple.CryptoTokenKit\" AND category == \"AHP\")'"
                ],
                "version": "3.1b43"
            },
            "event_score": 0,
            "host_info": {
                "host": {
                    "uuid": "3X6E4X3X-9285-4X7X-9X0X-X3X62XX379XX"
                }
            }
        }
    },
    "log": {
        "source": {
            "address": "192.168.224.7:58764"
        }
    },
    "related": {
        "hosts": [
            "macbook_pro"
        ],
        "user": [
            "dan@email.com"
        ]
    },
    "tags": [
        "forwarded",
        "jamf_protect_telemetry-log"
    ],
    "user": {
        "email": "dan@email.com"
    }
}
```

#### threats event stream

This is the `Threats Event Stream` dataset.

##### Example

An example event for `web_threat_events` looks as following:

```json
{
    "destination": {
        "address": "ip",
        "domain": "host",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "Detected",
        "category": [
            "host"
        ],
        "id": "013b15c9-8f62-4bf1-948a-d82367af2a10",
        "kind": "alert",
        "module": "Threat Events Stream",
        "provider": "Jamf Protect",
        "reason": "Sideloaded App",
        "severity": 6,
        "start": "2020-01-30T17:47:41.767Z",
        "url": "https://radar.wandera.com/security/events/detail/013b15c9-8f62-4bf1-948a-d82367af2a10.SIDE_LOADED_APP_IN_INVENTORY?createdUtcMs=1580406461767"
    },
    "file": {
        "hash": {
            "sha1": "16336078972773bc6c8cef69d722c8c093ba727ddc5bb31eb2",
            "sha256": "16336078978a306dc23b67dae9df18bc2a0205e3ff0cbf97c46e76fd670f93fd142d7042"
        },
        "name": "Books"
    },
    "host": {
        "geo": {
            "country_iso_code": "gb"
        },
        "hostname": "Apple iPhone 11",
        "id": "09f81436-de17-441e-a631-0461252c629b",
        "os": {
            "full": "IOS 11.2.5"
        }
    },
    "jamf_protect": {},
    "message": "{\"event\":{\"metadata\":{\"schemaVersion\":\"1.0\",\"vendor\":\"Jamf\",\"product\":\"Threat Events Stream\"},\"timestamp\":\"2020-01-30T17:47:41.767Z\",\"alertId\":\"013b15c9-8f62-4bf1-948a-d82367af2a10\",\"account\":{\"customerId\":\"fb4567b6-4ee2-3c4c-abb9-4c78ec463b25\",\"parentId\":\"7c302632-7ac4-4234-8ada-11d76feb3730\",\"name\":\"Customer\"},\"device\":{\"deviceId\":\"09f81436-de17-441e-a631-0461252c629b\",\"os\":\"IOS 11.2.5\",\"deviceName\":\"Apple iPhone 11 (11.2.5)\",\"userDeviceName\":\"Apple iPhone 11\",\"externalId\":\"5087dc0e-876c-4b0e-95ea-5b543476e0c4\"},\"eventType\":{\"id\":213,\"description\":\"Sideloaded App\",\"name\":\"SIDE_LOADED_APP_IN_INVENTORY\"},\"app\":{\"id\":\"com.apple.iBooks\",\"name\":\"Books\",\"version\":\"1.1\",\"sha1\":\"16336078972773bc6c8cef69d722c8c093ba727ddc5bb31eb2\",\"sha256\":\"16336078978a306dc23b67dae9df18bc2a0205e3ff0cbf97c46e76fd670f93fd142d7042\"},\"destination\":{\"name\":\"host\",\"ip\":\"ip\",\"port\":80},\"source\":{\"ip\":\"1.2.3.4\",\"port\":3025},\"location\":\"gb\",\"accessPoint\":\"AccessPoint\",\"accessPointBssid\":\"c6:9f:db:b1:73:5a\",\"severity\":6,\"user\":{\"email\":\"user@mail.com\",\"name\":\"John Doe\"},\"eventUrl\":\"https://radar.wandera.com/security/events/detail/013b15c9-8f62-4bf1-948a-d82367af2a10.SIDE_LOADED_APP_IN_INVENTORY?createdUtcMs=1580406461767\",\"action\":\"Detected\"}}",
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "organization": {
        "id": "fb4567b6-4ee2-3c4c-abb9-4c78ec463b25"
    },
    "rule": {
        "description": "Sideloaded App",
        "name": "SIDE_LOADED_APP_IN_INVENTORY"
    },
    "source": {
        "port": 3025
    },
    "user": {
        "email": "user@mail.com",
        "name": "John Doe"
    }
}
```

#### network traffic stream

This is the `Network Traffic Stream` dataset.

##### Example

An example event for `web_traffic_events` looks as following:

```json
{
    "dns": {
        "answers": {
            "ttl": 101,
            "type": "HTTPS"
        },
        "question": {
            "name": "s.youtube.com",
            "registered_domain": "youtube",
            "top_level_domain": "com"
        },
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "DNS Lookup",
        "category": [
            "host",
            "network"
        ],
        "kind": "event",
        "module": "Network Traffic Stream",
        "outcome": [
            "success"
        ],
        "provider": "Jamf Protect",
        "reason": "CLEAN",
        "start": "2024-02-02T06:26:04.273Z",
        "type": [
            "connection"
        ]
    },
    "host": {
        "id": "3453be41-0f2d-4d43-9ec2-a53f39fff93c",
        "os": {
            "type": [
                "ios"
            ]
        }
    },
    "interface": {
        "name": "WIFI"
    },
    "jamf_protect": {},
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "organization": {
        "id": "9608556b-0c3a-4a9c-9b4a-d714d8a028a1"
    },
    "rule": {
        "name": "DNS Lookup"
    },
    "user": {
        "email": "user@acme.com",
        "name": "07a5a2ae-16de-4767-831e-0ea8b7c3abe4"
    }
}
```