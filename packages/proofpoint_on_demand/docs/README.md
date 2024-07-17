# Proofpoint On Demand

Proofpoint on Demand is a cloud-based cybersecurity platform that offers a wide range of services to protect businesses against cyber threats. This includes email security, threat intelligence, information protection, and compliance solutions. The Proofpoint on Demand integration for Elastic provides insight into the functioning and effectiveness of your email security policies, allowing you to make informed decisions to improve security posture.

The Proofpoint On Demand integration collects data for Audit, Mail, and Message logs utilizing the Secure WebSocket (WSS) protocol for log streaming.

## Data streams

The Proofpoint On Demand integration collects data for the following three events:

| Event Type                    |
|-------------------------------|
| Audit                         |
| Mail                          |
| Message                       |

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

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#_minimum_requirements).

## Setup

### To collect data from the Proofpoint On Demand Log Service:

The **Cluster ID** is displayed in the upper-right corner of the management interface, next to the release number. Proofpoint will provide the token for each cluster.

**NOTE**: Proofpoint On Demand Log service requires a Remote Syslog Forwarding license. Please refer the [documentation](https://proofpointcommunities.force.com/community/s/article/Proofpoint-on-Demand-Pod-Log-API) on how to enable it.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Proofpoint On Demand.
3. Click on the "Proofpoint On Demand" integration from the search results.
4. Click on the "Add Proofpoint On Demand" button to add the integration.
5. Add all the required integration configuration parameters, including Cluster ID and Access Token, to enable data collection.
6. Click on "Save and continue" to save the integration.

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2023-10-30T06:13:37.162Z",
    "agent": {
        "ephemeral_id": "b91bfe40-a0b1-4d8d-a6b3-31349274c490",
        "id": "edea5fcb-b045-4791-8aee-17f9771265b4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "proofpoint_on_demand.audit",
        "namespace": "24289",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "edea5fcb-b045-4791-8aee-17f9771265b4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "login",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "proofpoint_on_demand.audit",
        "id": "792f514f-15cb-480d-825e-e3565d32f928",
        "ingested": "2024-07-17T16:30:44Z",
        "kind": "event",
        "original": "{\"audit\":{\"action\":\"login\",\"level\":\"INFO\",\"resourceType\":\"authorization\",\"tags\":[{\"name\":\"eventSubCategory\",\"value\":\"authorization\"},{\"name\":\"eventDetails\",\"value\":\"\"},{\"name\":\"login.authorization\",\"value\":\"true\"}],\"user\":{\"email\":\"bob@example.org\",\"id\":\"a7e6abcd-1234-7901-1234-abcdefc31236\",\"ipAddress\":\"1.128.0.0\"}},\"guid\":\"792f514f-15cb-480d-825e-e3565d32f928\",\"metadata\":{\"customerId\":\"c8215678-6e78-42dd-a327-abcde13f9cff\",\"origin\":{\"data\":{\"agent\":\"89.160.20.128\",\"cid\":\"pphosted_prodmgt_hosted\",\"version\":\"1.0\"},\"schemaVersion\":\"1.0\",\"type\":\"cadmin-api-gateway\"}},\"ts\":\"2023-10-30T06:13:37.162521+0000\"}",
        "type": [
            "start"
        ]
    },
    "input": {
        "type": "websocket"
    },
    "observer": {
        "ip": [
            "89.160.20.128"
        ],
        "name": "pphosted_prodmgt_hosted",
        "version": "1.0"
    },
    "proofpoint_on_demand": {
        "audit": {
            "action": "login",
            "guid": "792f514f-15cb-480d-825e-e3565d32f928",
            "level": "INFO",
            "metadata": {
                "customer_id": "c8215678-6e78-42dd-a327-abcde13f9cff",
                "origin": {
                    "data": {
                        "agent_ip": "89.160.20.128",
                        "cid": "pphosted_prodmgt_hosted",
                        "version": "1.0"
                    },
                    "schema_version": "1.0",
                    "type": "cadmin-api-gateway"
                }
            },
            "resource_type": "authorization",
            "tags": [
                {
                    "name": "eventSubCategory",
                    "value": "authorization"
                },
                {
                    "name": "eventDetails"
                },
                {
                    "name": "login.authorization",
                    "value": "true"
                }
            ],
            "ts": "2023-10-30T06:13:37.162Z",
            "user": {
                "email": "bob@example.org",
                "id": "a7e6abcd-1234-7901-1234-abcdefc31236",
                "ip_address": "1.128.0.0"
            }
        }
    },
    "related": {
        "ip": [
            "89.160.20.128",
            "1.128.0.0"
        ],
        "user": [
            "bob@example.org",
            "a7e6abcd-1234-7901-1234-abcdefc31236"
        ]
    },
    "source": {
        "ip": "1.128.0.0",
        "user": {
            "email": "bob@example.org",
            "id": "a7e6abcd-1234-7901-1234-abcdefc31236"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "proofpoint_on_demand-audit"
    ]
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
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| proofpoint_on_demand.audit.action | Resource action. | keyword |
| proofpoint_on_demand.audit.guid | Globally unique identifier for this message object. | keyword |
| proofpoint_on_demand.audit.level | Event log level. | keyword |
| proofpoint_on_demand.audit.metadata.customer_id | The customer ID. | keyword |
| proofpoint_on_demand.audit.metadata.origin.data.agent | The source host the audit event occurred. | keyword |
| proofpoint_on_demand.audit.metadata.origin.data.agent_ip |  | ip |
| proofpoint_on_demand.audit.metadata.origin.data.cid | The cluster ID license for the PPS deployment. | keyword |
| proofpoint_on_demand.audit.metadata.origin.data.version | The release PPS version. | keyword |
| proofpoint_on_demand.audit.metadata.origin.schema_version | Schema version of this message payload. | keyword |
| proofpoint_on_demand.audit.metadata.origin.type | The type of origin, i.e. PPS, Cloudmark, etc. | keyword |
| proofpoint_on_demand.audit.metadata.trace.id | Trace ID information for trafficstats needs. | keyword |
| proofpoint_on_demand.audit.metadata.trace.ts | Trace timestamp information for trafficstats needs. | date |
| proofpoint_on_demand.audit.resource_name | Resource name. | keyword |
| proofpoint_on_demand.audit.resource_type | Resource type. | keyword |
| proofpoint_on_demand.audit.service.cid | The cluster id from the IDM service token. | keyword |
| proofpoint_on_demand.audit.service.customer_id | The customer id of the service. | keyword |
| proofpoint_on_demand.audit.service.id | The IDM service id. | keyword |
| proofpoint_on_demand.audit.service.ip_address | The IP address of the service. | ip |
| proofpoint_on_demand.audit.tags.name | Tag name for the particular instance of event. | keyword |
| proofpoint_on_demand.audit.tags.value | The value associated with the tag name. | keyword |
| proofpoint_on_demand.audit.ts | Timestamp of when the event to be audited occurred. | date |
| proofpoint_on_demand.audit.user.email | User email address. | keyword |
| proofpoint_on_demand.audit.user.id | User ID. | keyword |
| proofpoint_on_demand.audit.user.ip_address | IP Address from where the user logged in. | ip |
| proofpoint_on_demand.audit.user.roles_assigned | User Authorization information. | keyword |


### Mail

This is the `Mail` dataset.

#### Example

An example event for `mail` looks as following:

```json
{
    "@timestamp": "2024-06-19T12:28:32.533Z",
    "agent": {
        "ephemeral_id": "2c2f1486-7b59-46be-8993-e51b90e0bd00",
        "id": "edea5fcb-b045-4791-8aee-17f9771265b4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "proofpoint_on_demand.mail",
        "namespace": "14309",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "edea5fcb-b045-4791-8aee-17f9771265b4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "to": {
            "address": [
                "<mailive@example.com>"
            ]
        },
        "x_mailer": "esmtp"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "proofpoint_on_demand.mail",
        "id": "NABCDefGH0/I1234slqccQ",
        "ingested": "2024-07-17T16:31:44Z",
        "kind": "event",
        "original": "{\"data\":\"2024-06-19T05:28:32.533564-07:00 m0000123 sendmail[17416]: 45ABSW12341234: to=\\u003cmailive@example.com\\u003e, delay=00:00:00, xdelay=00:00:00, mailer=esmtp, tls_verify=OK, tls_version=TLSv1.2, cipher=ECDHE-RSA-AES256-GCM, pri=121557, relay=test4.example.net. [216.160.83.56], dsn=2.0.0, stat=Sent (Ok: queued)\",\"id\":\"NABCDefGH0/I1234slqccQ\",\"metadata\":{\"customerId\":\"c82abcde-5678-42dd-1234-1234563f9cff\",\"origin\":{\"data\":{\"agent\":\"m0000123.ppops.net\",\"cid\":\"pphosted_prodmgt_hosted\"},\"schemaVersion\":\"20200420\"}},\"pps\":{\"agent\":\"m0000123.ppops.net\",\"cid\":\"pphosted_prodmgt_hosted\"},\"sm\":{\"delay\":\"00:00:00\",\"dsn\":\"2.0.0\",\"mailer\":\"esmtp\",\"pri\":\"121557\",\"qid\":\"45ABSW12341234\",\"relay\":\"test4.example.net. [216.160.83.56]\",\"stat\":\"Sent (Ok: queued)\",\"to\":[\"\\u003cmailive@example.com\\u003e\"],\"xdelay\":\"00:00:00\"},\"tls\":{\"cipher\":\"ECDHE-RSA-AES256-GCM\",\"verify\":\"OK\",\"version\":\"TLSv1.2\"},\"ts\":\"2024-06-19T05:28:32.533564-0700\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "websocket"
    },
    "message": "2024-06-19T05:28:32.533564-07:00 m0000123 sendmail[17416]: 45ABSW12341234: to=<mailive@example.com>, delay=00:00:00, xdelay=00:00:00, mailer=esmtp, tls_verify=OK, tls_version=TLSv1.2, cipher=ECDHE-RSA-AES256-GCM, pri=121557, relay=test4.example.net. [216.160.83.56], dsn=2.0.0, stat=Sent (Ok: queued)",
    "observer": {
        "hostname": "m0000123.ppops.net",
        "name": "pphosted_prodmgt_hosted",
        "product": "Proofpoint On Demand",
        "type": "mail-gateway",
        "vendor": "Proofpoint"
    },
    "proofpoint_on_demand": {
        "mail": {
            "data": "2024-06-19T05:28:32.533564-07:00 m0000123 sendmail[17416]: 45ABSW12341234: to=<mailive@example.com>, delay=00:00:00, xdelay=00:00:00, mailer=esmtp, tls_verify=OK, tls_version=TLSv1.2, cipher=ECDHE-RSA-AES256-GCM, pri=121557, relay=test4.example.net. [216.160.83.56], dsn=2.0.0, stat=Sent (Ok: queued)",
            "id": "NABCDefGH0/I1234slqccQ",
            "metadata": {
                "origin": {
                    "data": {
                        "agent": "m0000123.ppops.net",
                        "cid": "pphosted_prodmgt_hosted"
                    }
                }
            },
            "pps": {
                "agent": "m0000123.ppops.net",
                "cid": "pphosted_prodmgt_hosted"
            },
            "sm": {
                "delay": "00:00:00",
                "dsn": "2.0.0",
                "mailer": "esmtp",
                "priority": 121557,
                "qid": "45ABSW12341234",
                "relay": "test4.example.net. [216.160.83.56]",
                "status": "Sent (Ok: queued)",
                "to": [
                    "<mailive@example.com>"
                ],
                "xdelay": "00:00:00"
            },
            "tls": {
                "cipher": "ECDHE-RSA-AES256-GCM",
                "verify": "OK",
                "version": "TLSv1.2"
            },
            "ts": "2024-06-19T12:28:32.533Z"
        }
    },
    "related": {
        "hosts": [
            "m0000123.ppops.net"
        ],
        "user": [
            "<mailive@example.com>"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "proofpoint_on_demand-mail"
    ],
    "tls": {
        "cipher": "ECDHE-RSA-AES256-GCM",
        "version": "1.2",
        "version_protocol": "tls"
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
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| proofpoint_on_demand.mail.data | The raw data that corresponds to one log line from maillog. | keyword |
| proofpoint_on_demand.mail.id | A unique ID for the object. | keyword |
| proofpoint_on_demand.mail.metadata.origin.data.agent |  | keyword |
| proofpoint_on_demand.mail.metadata.origin.data.cid |  | keyword |
| proofpoint_on_demand.mail.metadata.origin.data.version |  | keyword |
| proofpoint_on_demand.mail.pps.agent | The FQDN of the source agent on which the mail log line is produced. | keyword |
| proofpoint_on_demand.mail.pps.cid | The cluster ID from which the data log line originated. | keyword |
| proofpoint_on_demand.mail.pps.version |  | keyword |
| proofpoint_on_demand.mail.sm.auth |  | keyword |
| proofpoint_on_demand.mail.sm.class | The class (i.e., numeric precedence) of the message. | long |
| proofpoint_on_demand.mail.sm.ctladdr | The "controlling user", that is, the name of the user whose credentials are used for delivery. | keyword |
| proofpoint_on_demand.mail.sm.daemon | The daemon name from the DaemonPortOptions setting. | keyword |
| proofpoint_on_demand.mail.sm.delay | The total message delay: (the time difference between reception and final delivery or bounce). Format is delay=HH:MM::SS for a delay of less than one day and delay=days+HH:MM::SS otherwise. | keyword |
| proofpoint_on_demand.mail.sm.dsn | The enhanced error code (RFC2034) if available. | keyword |
| proofpoint_on_demand.mail.sm.from | The envelope sender address. | keyword |
| proofpoint_on_demand.mail.sm.mailer | The name of the mailer used to deliver to this recipient. | keyword |
| proofpoint_on_demand.mail.sm.msgid | The message id of the message (from the header). | keyword |
| proofpoint_on_demand.mail.sm.nrcpts | The number of envelope recipients for this message (after aliasing and forwarding). | long |
| proofpoint_on_demand.mail.sm.priority | The initial message priority (used for queue sorting). | long |
| proofpoint_on_demand.mail.sm.protocol | The protocol used to receive this message (e.g., ESMTP or UUCP). | keyword |
| proofpoint_on_demand.mail.sm.qid | The corresponding sendmail queue ID for the log line. | keyword |
| proofpoint_on_demand.mail.sm.relay | Shows which user or system sent / received the message; the format is one of relay=user(a)domain [IP], relay=user(a)localhost, or relay=fqdn host. | keyword |
| proofpoint_on_demand.mail.sm.size_bytes | The size of the incoming message in bytes during the DATA phase, including end-of-line characters. | long |
| proofpoint_on_demand.mail.sm.status | The delivery status of the message. | keyword |
| proofpoint_on_demand.mail.sm.tls.verify | The tls_verify data is included in two log lines. When the data appears in the from= log line, it describes TLS results when the message was received by the Proofpoint Protection Server. When the data appears in the to= log line, it describes TLS results when the message was sent from the Proofpoint Protection Server. | keyword |
| proofpoint_on_demand.mail.sm.to | Recipients to this mailer. | keyword |
| proofpoint_on_demand.mail.sm.xdelay | The total time the message took to be transmitted during final delivery. This differs from the delay= equate, in that the xdelay= equate only counts the time in the actual final delivery. | keyword |
| proofpoint_on_demand.mail.tls.cipher |  | keyword |
| proofpoint_on_demand.mail.tls.verify |  | keyword |
| proofpoint_on_demand.mail.tls.version |  | keyword |
| proofpoint_on_demand.mail.ts | Timestamp of logging time in ISO8601 format. | date |


### Message

This is the `Message` dataset.

#### Example

An example event for `message` looks as following:

```json
{
    "@timestamp": "2024-05-22T19:10:03.058Z",
    "agent": {
        "ephemeral_id": "c7399ce4-1dc3-4ecd-8600-6b2eefabf8c4",
        "id": "edea5fcb-b045-4791-8aee-17f9771265b4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "proofpoint_on_demand.message",
        "namespace": "50314",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "edea5fcb-b045-4791-8aee-17f9771265b4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "from": {
            "address": [
                "\"(Cron Daemon)\" <pps@m0000123.ppops.net>"
            ]
        },
        "message_id": [
            "<212345678910.44ABCDE1231370@m0000123.ppops.net>"
        ],
        "sender": {
            "address": "pps@m0000123.ppops.net"
        },
        "subject": [
            "Cron <pps@m0000123> /opt/proofpoint/resttimer.pl"
        ],
        "to": {
            "address": [
                "pps@m0000123.ppops.net"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "proofpoint_on_demand.message",
        "duration": 118720000,
        "id": "vRq4ZIFWHXbuABCDEFghij0U4VvIc71x",
        "ingested": "2024-07-17T16:33:05Z",
        "kind": "event",
        "original": "{\"connection\":{\"country\":\"**\",\"helo\":\"m0000123.ppops.net\",\"host\":\"localhost\",\"ip\":\"127.0.0.1\",\"protocol\":\"smtp:smtp\",\"resolveStatus\":\"ok\",\"sid\":\"3y8abcd123\",\"tls\":{\"inbound\":{\"cipher\":\"ECDHE-RSA-AES256-GCM-SHA384\",\"cipherBits\":256,\"version\":\"TLSv1.2\"}}},\"envelope\":{\"from\":\"pps@m0000123.ppops.net\",\"rcpts\":[\"pps@m0000123.ppops.net\"]},\"filter\":{\"actions\":[{\"action\":\"accept\",\"isFinal\":true,\"module\":\"access\",\"rule\":\"system\"}],\"delivered\":{\"rcpts\":[\"pps@m0000123.ppops.net\"]},\"disposition\":\"accept\",\"durationSecs\":0.11872,\"msgSizeBytes\":1127,\"qid\":\"44ABCDm0000123\",\"routeDirection\":\"outbound\",\"routes\":[\"allow_relay\",\"firewallsafe\"],\"suborgs\":{\"rcpts\":[\"0\"],\"sender\":\"0\"},\"verified\":{\"rcpts\":[\"pps@m0000123.ppops.net\"]}},\"guid\":\"vRq4ZIFWHXbuABCDEFghij0U4VvIc71x\",\"metadata\":{\"origin\":{\"data\":{\"agent\":\"m0000123.ppops.net\",\"cid\":\"pphosted_prodmgt_hosted\",\"version\":\"8.21.0.1358\"}}},\"msg\":{\"header\":{\"from\":[\"\\\"(Cron Daemon)\\\" \\u003cpps@m0000123.ppops.net\\u003e\"],\"message-id\":[\"\\u003c212345678910.44ABCDE1231370@m0000123.ppops.net\\u003e\"],\"subject\":[\"Cron \\u003cpps@m0000123\\u003e /opt/proofpoint/resttimer.pl\"],\"to\":[\"pps@m0000123.ppops.net\"]},\"lang\":\"\",\"normalizedHeader\":{\"from\":[\"\\\"(Cron Daemon)\\\" \\u003cpps@m0000123.ppops.net\\u003e\"],\"message-id\":[\"212345678910.44ABCDE1231370@m0000123.ppops.net\"],\"subject\":[\"Cron \\u003cpps@m0000123\\u003e /opt/proofpoint/resttimer.pl\"],\"to\":[\"pps@m0000123.ppops.net\"]},\"parsedAddresses\":{},\"sizeBytes\":1151},\"msgParts\":[],\"ts\":\"2024-05-22T12:10:03.058340-0700\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "websocket"
    },
    "network": {
        "direction": "outbound",
        "protocol": "smtp"
    },
    "observer": {
        "hostname": "m0000123.ppops.net",
        "name": "pphosted_prodmgt_hosted",
        "product": "Proofpoint On Demand",
        "type": "mail-gateway",
        "vendor": "Proofpoint",
        "version": "8.21.0.1358"
    },
    "proofpoint_on_demand": {
        "message": {
            "connection": {
                "helo": "m0000123.ppops.net",
                "host": "localhost",
                "ip": "127.0.0.1",
                "protocol": "smtp:smtp",
                "resolve_status": "ok",
                "sid": "3y8abcd123",
                "tls": {
                    "inbound": {
                        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
                        "cipher_bits": 256,
                        "version": "TLSv1.2"
                    }
                }
            },
            "envelope": {
                "from": "pps@m0000123.ppops.net",
                "rcpts": [
                    "pps@m0000123.ppops.net"
                ]
            },
            "filter": {
                "actions": [
                    {
                        "action": "accept",
                        "is_final": true,
                        "module": "access",
                        "rule": "system"
                    }
                ],
                "disposition": "accept",
                "duration_secs": 0.11872,
                "msg_size_bytes": 1127,
                "qid": "44ABCDm0000123",
                "route_direction": "outbound",
                "routes": [
                    "allow_relay",
                    "firewallsafe"
                ],
                "verified": {
                    "rcpts": [
                        "pps@m0000123.ppops.net"
                    ]
                }
            },
            "guid": "vRq4ZIFWHXbuABCDEFghij0U4VvIc71x",
            "metadata": {
                "origin": {
                    "data": {
                        "agent": "m0000123.ppops.net",
                        "cid": "pphosted_prodmgt_hosted",
                        "version": "8.21.0.1358"
                    }
                }
            },
            "msg": {
                "header": {
                    "from": [
                        "\"(Cron Daemon)\" <pps@m0000123.ppops.net>"
                    ],
                    "message_id": [
                        "<212345678910.44ABCDE1231370@m0000123.ppops.net>"
                    ],
                    "subject": [
                        "Cron <pps@m0000123> /opt/proofpoint/resttimer.pl"
                    ],
                    "to": [
                        "pps@m0000123.ppops.net"
                    ]
                },
                "normalized_header": {
                    "from": [
                        "\"(Cron Daemon)\" <pps@m0000123.ppops.net>"
                    ],
                    "message_id": [
                        "212345678910.44ABCDE1231370@m0000123.ppops.net"
                    ],
                    "subject": [
                        "Cron <pps@m0000123> /opt/proofpoint/resttimer.pl"
                    ],
                    "to": [
                        "pps@m0000123.ppops.net"
                    ]
                },
                "size_bytes": 1151
            },
            "ts": "2024-05-22T19:10:03.058Z"
        }
    },
    "related": {
        "hosts": [
            "m0000123.ppops.net",
            "localhost"
        ],
        "ip": [
            "127.0.0.1"
        ],
        "user": [
            "pps@m0000123.ppops.net",
            "\"(Cron Daemon)\" <pps@m0000123.ppops.net>"
        ]
    },
    "source": {
        "address": "m0000123.ppops.net",
        "domain": "localhost",
        "ip": "127.0.0.1"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "proofpoint_on_demand-message"
    ],
    "tls": {
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "version": "1.2",
        "version_protocol": "tls"
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
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| proofpoint_on_demand.message.action_dkimv.action |  | keyword |
| proofpoint_on_demand.message.action_dkimv.module |  | keyword |
| proofpoint_on_demand.message.action_dkimv.rule |  | keyword |
| proofpoint_on_demand.message.action_dmarc.action |  | keyword |
| proofpoint_on_demand.message.action_dmarc.module |  | keyword |
| proofpoint_on_demand.message.action_dmarc.rule |  | keyword |
| proofpoint_on_demand.message.action_spf.action |  | keyword |
| proofpoint_on_demand.message.action_spf.module |  | keyword |
| proofpoint_on_demand.message.action_spf.rule |  | keyword |
| proofpoint_on_demand.message.connection.country | The country code of the sender IP. | keyword |
| proofpoint_on_demand.message.connection.helo | The FQDN or IP reported via the HELO or EHLO command. | keyword |
| proofpoint_on_demand.message.connection.host | The host name of the reverse lookup of the sender IP. | keyword |
| proofpoint_on_demand.message.connection.ip | The sender IP in IPv4 or IPv6 format. | ip |
| proofpoint_on_demand.message.connection.protocol | The connection protocol info. | keyword |
| proofpoint_on_demand.message.connection.resolve_status | Can the sender IP be resolved with a reverse lookup. | keyword |
| proofpoint_on_demand.message.connection.sid | The ID of the connection/session object; this is otherwise known as the "sid" in filter.log. | keyword |
| proofpoint_on_demand.message.connection.tls.inbound.cipher | Inbound TLS cipher algorithm detected. | keyword |
| proofpoint_on_demand.message.connection.tls.inbound.cipher_bits | Inbound TLS cipher algorithm strength (in #bits). | long |
| proofpoint_on_demand.message.connection.tls.inbound.policy | Inbound TLS policy. | keyword |
| proofpoint_on_demand.message.connection.tls.inbound.version | Inbound TLS protocol version. | keyword |
| proofpoint_on_demand.message.envelope.from | The envelope sender. | keyword |
| proofpoint_on_demand.message.envelope.from_hashed |  | keyword |
| proofpoint_on_demand.message.envelope.rcpts | The envelope recipients. | keyword |
| proofpoint_on_demand.message.envelope.rcpts_hashed |  | keyword |
| proofpoint_on_demand.message.filter.actions.action |  | keyword |
| proofpoint_on_demand.message.filter.actions.is_final |  | boolean |
| proofpoint_on_demand.message.filter.actions.module |  | keyword |
| proofpoint_on_demand.message.filter.actions.rule |  | keyword |
| proofpoint_on_demand.message.filter.current_folder | The folder to which the message is currently assigned. | keyword |
| proofpoint_on_demand.message.filter.disposition | The message disposition string as determined by filterd (the filtering engine daemon). | keyword |
| proofpoint_on_demand.message.filter.duration_secs | Time spent processing the message. | double |
| proofpoint_on_demand.message.filter.is_msg_encrypted | Is the message encrypted. | boolean |
| proofpoint_on_demand.message.filter.is_msg_reinjected | Was the message reinjected. | boolean |
| proofpoint_on_demand.message.filter.mid | The message id. | keyword |
| proofpoint_on_demand.message.filter.modules.av.virus_names | The virus names reported by the AV module. | keyword |
| proofpoint_on_demand.message.filter.modules.dkimv.domain | The DKIM d= value in the signature line. | keyword |
| proofpoint_on_demand.message.filter.modules.dkimv.result | The DKIM result. | keyword |
| proofpoint_on_demand.message.filter.modules.dkimv.selector | The DKIM s= value in the signature line. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.alignment.from_domain | The DMARC TLD from the MAIL FROM data. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.alignment.results.identity | The DMARC domain identity as reported in the signature. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.alignment.results.identity_org | The DMARC identifying organization as a Top Level Domain. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.alignment.results.method | The DMARC method involved for an alignment result object. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.alignment.results.result | The DMARC result involved for the alignment result object. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.email_identities.header.from | The header.from email identity for a DMARC authorization result object. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.email_identities.smtp.helo | The smtp.helo email identity for a DMARC authorization result object. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.email_identities.smtp.mailfrom | The smtp.mailfrom email identity for a DMARC authorization result object. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.email_identities.smtp.mailfrom_hashed |  | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.method | The authorization result method. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.propspec.header.d |  | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.propspec.header.s | The header.s value for the property specification for the authorization result per DMARC spec. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.reason | The reason string for the authorization result. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.auth_results.result | The result value for the authorization result. | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.filterd_result | The rollup DMARC result (generated by filterd for the rules, i.e. $dmarcresult). | keyword |
| proofpoint_on_demand.message.filter.modules.dmarc.records | The actual raw DMARC TXT record. | nested |
| proofpoint_on_demand.message.filter.modules.dmarc.srvid | DMARC Auth Service ID as defined in filter.cfg. | keyword |
| proofpoint_on_demand.message.filter.modules.pdr.v1.rscore | The PDR (Proofpoint Dynamic Reputation) v1 rscore value. | long |
| proofpoint_on_demand.message.filter.modules.pdr.v1.spamscore | The PDR v1 spamscore value. | long |
| proofpoint_on_demand.message.filter.modules.pdr.v1.virusscore | The PDR v1 virusscore value. | long |
| proofpoint_on_demand.message.filter.modules.pdr.v2.response | The PDR v2 response status. | keyword |
| proofpoint_on_demand.message.filter.modules.pdr.v2.rscore | The PDR v2 rscore value. | long |
| proofpoint_on_demand.message.filter.modules.sandbox.error_status | The Attachment Defense error status string. | keyword |
| proofpoint_on_demand.message.filter.modules.spam.triggered_classifier | The one spam classifier as defined by policy rules that determined the spam disposition. | keyword |
| proofpoint_on_demand.message.filter.modules.spf.domain |  | keyword |
| proofpoint_on_demand.message.filter.modules.spf.result | The SPF (Sender Policy Framework) result. | keyword |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.max_limit | The configured defined maximum number of unique URLs the URL Defense Module can process. | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_content_type_text | The total number of URLs that the URL Defense did not rewrite due to "is content type text". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_email | The total number of URLs the URL Defense Module did not rewrite due to "is email". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_excluded_domain | The total number of URLs the URL Defense Module did not rewrite due to "is excluded domain". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_large_msgpart_size | The total number of URLs the URL Defense Module did not rewrite due to "is large message part size". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_maxlength_exceeded | The total number of URLs the URL Defense Module did not rewrite due to "is max length exceeded". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_schemeless | The total number of URLs the URL Defense Module did not rewrite due to "is schemeless". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.no_rewrite.is_unsupported_scheme | The total number of URLs the URL Defense Module did not rewrite due to "is unsupported scheme". | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.rewritten | The total number of URLs the URL Defense Module rewrote. | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.total | The total number of URLs the URL Defense processed. | long |
| proofpoint_on_demand.message.filter.modules.urldefense.counts.unique | The total unique number of URLs the URL Defense Module processed. | long |
| proofpoint_on_demand.message.filter.modules.urldefense.rewritten_urls | The URLs rewritten by URL Defense. | keyword |
| proofpoint_on_demand.message.filter.modules.urldefense.version.engine | Engine version for the URL Defense Module. | keyword |
| proofpoint_on_demand.message.filter.modules.zerohour.score | The ZeroHour threat score. | keyword |
| proofpoint_on_demand.message.filter.msg_size_bytes | The size of the email in bytes. | long |
| proofpoint_on_demand.message.filter.orig_guid | The parent GUID for the message from which the current message was split. | keyword |
| proofpoint_on_demand.message.filter.pe.rcpts | Recipients encrypted via Proofpoint Encryption. | keyword |
| proofpoint_on_demand.message.filter.pe.rcpts_object | Recipients encrypted via Proofpoint Encryption. | nested |
| proofpoint_on_demand.message.filter.qid | The sendmail queue ID. | keyword |
| proofpoint_on_demand.message.filter.quarantine.folder | Quarantine folder containing a copy of the message. | keyword |
| proofpoint_on_demand.message.filter.quarantine.rule | Rule that causes the message to be quarantined. | keyword |
| proofpoint_on_demand.message.filter.route_direction |  | keyword |
| proofpoint_on_demand.message.filter.routes | The policy routes triggered by the message. | keyword |
| proofpoint_on_demand.message.filter.smime.rcpts | Recipients encrypted via S/MIME. | keyword |
| proofpoint_on_demand.message.filter.smime.signed_rcpts | Recipients signed and encrypted via S/MIME. | keyword |
| proofpoint_on_demand.message.filter.start_time | Timestamp for when message processing begins. | date |
| proofpoint_on_demand.message.filter.suborgs.rcpts |  | keyword |
| proofpoint_on_demand.message.filter.suborgs.sender |  | keyword |
| proofpoint_on_demand.message.filter.throttle_ip | The IP address being rate-controlled. | ip |
| proofpoint_on_demand.message.filter.verified.rcpts | Verified recipients. | keyword |
| proofpoint_on_demand.message.filter.verified.rcpts_hashed |  | keyword |
| proofpoint_on_demand.message.final_action |  | keyword |
| proofpoint_on_demand.message.final_module |  | keyword |
| proofpoint_on_demand.message.final_rule |  | keyword |
| proofpoint_on_demand.message.guid | Globally unique identifier for the message object. | keyword |
| proofpoint_on_demand.message.metadata.origin.data.agent |  | keyword |
| proofpoint_on_demand.message.metadata.origin.data.cid |  | keyword |
| proofpoint_on_demand.message.metadata.origin.data.version |  | keyword |
| proofpoint_on_demand.message.msg.header.cc | Carbon copy of email addresses. | keyword |
| proofpoint_on_demand.message.msg.header.from | The header sender. | keyword |
| proofpoint_on_demand.message.msg.header.from_hashed |  | keyword |
| proofpoint_on_demand.message.msg.header.message_id | The header message-id. | keyword |
| proofpoint_on_demand.message.msg.header.reply_to | The header Reply to address. | keyword |
| proofpoint_on_demand.message.msg.header.return_path | The header return path address. | keyword |
| proofpoint_on_demand.message.msg.header.subject | The header subject. | keyword |
| proofpoint_on_demand.message.msg.header.to | The header recipients. | keyword |
| proofpoint_on_demand.message.msg.header.to_hashed |  | keyword |
| proofpoint_on_demand.message.msg.lang | The detected language of the message. | keyword |
| proofpoint_on_demand.message.msg.normalized_header.cc |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.from |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.from_hashed |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.message_id |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.reply_to |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.return_path |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.subject |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.to |  | keyword |
| proofpoint_on_demand.message.msg.normalized_header.to_hashed |  | keyword |
| proofpoint_on_demand.message.msg.parsed_addresses.cc |  | keyword |
| proofpoint_on_demand.message.msg.parsed_addresses.from |  | keyword |
| proofpoint_on_demand.message.msg.parsed_addresses.from_hashed |  | keyword |
| proofpoint_on_demand.message.msg.parsed_addresses.to |  | keyword |
| proofpoint_on_demand.message.msg.parsed_addresses.to_hashed |  | keyword |
| proofpoint_on_demand.message.msg.size_bytes | The original, raw message size in bytes. | long |
| proofpoint_on_demand.message.msg_parts.database64 |  | keyword |
| proofpoint_on_demand.message.msg_parts.detected_charset | The detected charset of the message part. | keyword |
| proofpoint_on_demand.message.msg_parts.detected_ext | The detected extension of the message part. | keyword |
| proofpoint_on_demand.message.msg_parts.detected_mime | The detected MIME type of the message part. | keyword |
| proofpoint_on_demand.message.msg_parts.detected_name | The detected file name of the message part. | keyword |
| proofpoint_on_demand.message.msg_parts.detected_size_bytes | The detected file size of the message part in bytes. | long |
| proofpoint_on_demand.message.msg_parts.disposition | The content disposition value. | keyword |
| proofpoint_on_demand.message.msg_parts.is_archive | Is the message part an archive type. | boolean |
| proofpoint_on_demand.message.msg_parts.is_corrupted | Is the message part corrupted. | boolean |
| proofpoint_on_demand.message.msg_parts.is_deleted | Is the message part deleted. | boolean |
| proofpoint_on_demand.message.msg_parts.is_protected | Is the message part password protected. | boolean |
| proofpoint_on_demand.message.msg_parts.is_timed_out | Did the message part analysis or text extraction time out. | boolean |
| proofpoint_on_demand.message.msg_parts.is_virtual | Is the message part virtual (a file member in an archive type of attachment). | boolean |
| proofpoint_on_demand.message.msg_parts.labeled_charset | The charset of the message part as given. | keyword |
| proofpoint_on_demand.message.msg_parts.labeled_ext | The extension of the attachment as given. | keyword |
| proofpoint_on_demand.message.msg_parts.labeled_mime | The detected MIME type of the message part as given. | keyword |
| proofpoint_on_demand.message.msg_parts.labeled_name | The name of the message part as given. | keyword |
| proofpoint_on_demand.message.msg_parts.md5 | The ID of the message part in MD5. | keyword |
| proofpoint_on_demand.message.msg_parts.metadata | The metadata of the message part as reported by cvtd (interface to the document extraction engine). | object |
| proofpoint_on_demand.message.msg_parts.sandbox_status | The sandbox module status for the message part. | keyword |
| proofpoint_on_demand.message.msg_parts.sha256 | The ID of the message part in SHA256. | keyword |
| proofpoint_on_demand.message.msg_parts.size_decoded_bytes | The size of the decoded message part in bytes. | long |
| proofpoint_on_demand.message.msg_parts.structure_id | The Structural ID of the message part with respect to container type attachments. | keyword |
| proofpoint_on_demand.message.msg_parts.text_extracted |  | keyword |
| proofpoint_on_demand.message.msg_parts.urls.is_rewritten | Whether the URL was rewritten by URL Defense. | boolean |
| proofpoint_on_demand.message.msg_parts.urls.not_rewritten_reason | The reason why the corresponding URL was not rewritten by URL Defense. The value is an empty string if it was rewritten. | keyword |
| proofpoint_on_demand.message.msg_parts.urls.src | The PPS sources that detected the URL. | keyword |
| proofpoint_on_demand.message.msg_parts.urls.url | The URL found in the corresponding message part. | keyword |
| proofpoint_on_demand.message.pps.agent | The source/MFA host from which the email was received. | keyword |
| proofpoint_on_demand.message.pps.cid | The cluster ID license for the PPS deployment. | keyword |
| proofpoint_on_demand.message.pps.version | The release PPS version. | keyword |
| proofpoint_on_demand.message.ts |  | date |
