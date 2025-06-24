# Elastic Security

## Overview

Elastic Security Alerts are triggered when detection rules identify suspicious or malicious activity. They provide detailed context like rule name, impacted entities, timestamps, and other necessary details. Alerts can be investigated in Kibana using tools like Timeline. They support custom actions such as notifications or automated responses. These alerts help prioritize and manage security threats efficiently.

## Data streams

This integration collects the following logs:

`alert`: - Retrieve alerts from Elastic Instance.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### To collect data from the Elastic API:

To collect data from the Elastic API, you will need the following information:

1. The URL for the Elasticsearch instance.
2. Authentication credentials such as username, password, API key, or bearer token depend on the selected authentication type.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Elastic Security**.
3. Select the **Elastic Security** integration and add it.
4. Add all the required integration configuration parameters such as username, password, API key, or bearer token depend on the selected authentication type to enable data collection.
5. Select "Save and continue" to save the integration.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2060-06-09T13:56:03.205Z",
    "Endpoint": {
        "policy": {
            "applied": {
                "artifacts": {
                    "global": {
                        "identifiers": [
                            {
                                "name": "diagnostic-configuration-v1",
                                "sha256": "BBBBB40ca79cf0e165053daac3e4df8b428dea81c8d20edefca330d77bc0958c1"
                            },
                            {
                                "name": "diagnostic-endpointelf-v1-blocklist",
                                "sha256": "bbbbcb66f9337eb33f5c0359f51ad37761ff13e4a7c4be390e03d2c227ac7cf6"
                            },
                            {
                                "name": "diagnostic-endpointelf-v1-exceptionlist",
                                "sha256": "bbb2da99e044ecc7d50cea407bf17f33c546e5309aa7ee661234baed2b7750"
                            },
                            {
                                "name": "diagnostic-endpointelf-v1-model",
                                "sha256": "bbb0b5bb99b3b875f51678efae67874bae37bfcc0036ad86bd2f7cbf767824"
                            },
                            {
                                "name": "diagnostic-malware-signature-v1-linux",
                                "sha256": "bbb1dc5dabd9b0653fe08c856ce6488dc94999522c4548af2c71d4b62754d9a"
                            },
                            {
                                "name": "diagnostic-rules-linux-v1",
                                "sha256": "accfa58fca69040d49731d334770b96d88ca82c26c0e42b02908f2fcb7acf"
                            },
                            {
                                "name": "endpointelf-v1-blocklist",
                                "sha256": "0d43a899fb1e8389d36e95c87b1ed852661fc007041d41b45929a3b34f4"
                            },
                            {
                                "name": "endpointelf-v1-exceptionlist",
                                "sha256": "eb9689fb8b88f6fde235f1d5d9329c3056a21e6f451e36f23604ff8394"
                            },
                            {
                                "name": "endpointelf-v1-model",
                                "sha256": "ae994398f94f2bef6f2418b103935ac731db362dd74de9bfe4b490c61cf"
                            },
                            {
                                "name": "global-configuration-v1",
                                "sha256": "d0806a4f21ae4a2bd5889f2a179e764b3f0d9707bee8c5ec4668d9d88"
                            },
                            {
                                "name": "global-eventfilterlist-linux-v1",
                                "sha256": "8edb9a6739c50fbb25f49376983ca5ed8d3e79d710a43b01369c8c"
                            },
                            {
                                "name": "global-exceptionlist-linux",
                                "sha256": "efb487bf50555cece86abacb6b6e803d428ff1093e662ad5babb649"
                            },
                            {
                                "name": "global-trustlist-linux-v1",
                                "sha256": "614b22f442f53135ad6ddfa84e5f5cbfb0cb7d8f5a141d22645d589986"
                            },
                            {
                                "name": "production-malware-signature-v1-linux",
                                "sha256": "b60abcb862c755e47b106cfdcee07061068423c20e23d320831a40c6f6"
                            },
                            {
                                "name": "production-rules-linux-v1",
                                "sha256": "7b0f97917e6675e54a7f52799ace2a0d6b9ef6cccca6a0423b591e32be"
                            },
                            {
                                "name": "tamper-protection-config-v1",
                                "sha256": "07f2afe84d3b52b6cd8b841f33ffe6eb8e2297cefd4eaa3e50e567b4d30e"
                            }
                        ],
                        "snapshot": "latest",
                        "update_age": 0,
                        "version": "1.0.1049"
                    },
                    "user": {
                        "identifiers": [
                            {
                                "name": "endpoint-blocklist-linux-v1",
                                "sha256": "d801aacc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"
                            },
                            {
                                "name": "endpoint-eventfilterlist-linux-v1",
                                "sha256": "d801aa1330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"
                            },
                            {
                                "name": "endpoint-exceptionlist-linux-v1",
                                "sha256": "d801aa1330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"
                            },
                            {
                                "name": "endpoint-hostisolationexceptionlist-linux-v1",
                                "sha256": "d801aa1330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"
                            },
                            {
                                "name": "endpoint-trustlist-linux-v1",
                                "sha256": "d801aa1330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"
                            }
                        ],
                        "version": "1.0.0"
                    }
                }
            }
        }
    },
    "Events": [
        {
            "@timestamp": "2060-06-09T13:52:06.9710234Z",
            "_label": "script_executed",
            "_state": 0,
            "event": {
                "action": "exec",
                "category": [
                    "process"
                ],
                "created": "2024-06-09T13:52:06.9710234Z",
                "id": "Na7UF0/g6QHP1vOo++++3Y8t",
                "kind": "event",
                "outcome": "unknown",
                "type": [
                    "start"
                ]
            },
            "group": {
                "Ext": {
                    "real": {
                        "id": 1006,
                        "name": "admin"
                    }
                },
                "id": 1006,
                "name": "admin"
            },
            "message": "Endpoint process event",
            "process": {
                "Ext": {
                    "ancestry": [
                        "YYYYYY4NDYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNS0xNzE3OTQxMTI0",
                        "YYYYYY4NDYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MS0xNzE3OTQxMTIx",
                        "YYYYYY4NDYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MC0xNzE3OTQxMTIx",
                        "YYYYYY4NDYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE4OS0xNzE3OTQxMTIx",
                        "YYYYYY4NDYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTg5NS0xNzE3NzIzMDMw",
                        "YYYYYY4NDYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTEtMTcxNzcyMzAyMQ=="
                    ]
                },
                "args": [
                    "/tmp/bash",
                    "exec(base64.b64decode*abcdef)"
                ],
                "args_count": 2,
                "command_line": "/tmp/bash exec(base64.b64decode*abcdef)",
                "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNi0xNzE3OTQxMTI2",
                "entry_leader": {
                    "args": [
                        "/usr/sbin/cron",
                        "-f"
                    ],
                    "args_count": 2,
                    "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTg5NS0xNzE3NzIzMDMw",
                    "entry_meta": {
                        "type": "init"
                    },
                    "executable": "/usr/sbin/cron",
                    "group": {
                        "id": 0,
                        "name": "root"
                    },
                    "interactive": false,
                    "name": "cron",
                    "parent": {
                        "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTEtMTcxNzcyMzAyMQ==",
                        "pid": 1,
                        "start": "2024-06-07T01:17:01.19Z"
                    },
                    "pid": 895,
                    "real_group": {
                        "id": 0,
                        "name": "root"
                    },
                    "real_user": {
                        "id": 0,
                        "name": "root"
                    },
                    "same_as_process": false,
                    "start": "2024-06-07T01:17:10.36Z",
                    "user": {
                        "id": 0,
                        "name": "root"
                    },
                    "working_directory": "/var/spool/cron"
                },
                "executable": "/tmp/bash",
                "group": {
                    "id": 1006,
                    "name": "admin"
                },
                "group_leader": {
                    "args": [
                        "/bin/sh",
                        "-c",
                        "/tmp/rta-random-attack.sh > /tmp/rta-random.log 2>&1"
                    ],
                    "args_count": 3,
                    "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MC0xNzE3OTQxMTIx",
                    "executable": "/bin/sh",
                    "group": {
                        "id": 1006,
                        "name": "admin"
                    },
                    "interactive": false,
                    "name": "sh",
                    "pid": 141190,
                    "real_group": {
                        "id": 1006,
                        "name": "admin"
                    },
                    "real_user": {
                        "id": 1005,
                        "name": "admin"
                    },
                    "same_as_process": false,
                    "start": "2024-06-09T13:52:01.51Z",
                    "supplemental_groups": [
                        {
                            "id": 4,
                            "name": "adm"
                        },
                        {
                            "id": 30,
                            "name": "dip"
                        },
                        {
                            "id": 44,
                            "name": "video"
                        },
                        {
                            "id": 46,
                            "name": "plugdev"
                        },
                        {
                            "id": 1000,
                            "name": "google-sudoers"
                        }
                    ],
                    "user": {
                        "id": 1005,
                        "name": "admin"
                    },
                    "working_directory": "/home/admin"
                },
                "hash": {
                    "md5": "f9bf2d21a340f2b3ee534fba5b29e417",
                    "sha1": "21a5d9c728d069ba6239c1da751a2f31fba9b1aa",
                    "sha256": "d9df3091f6093bd9a7b308e536fbc285aeef2c5139577cc96bc594a4845f0e13"
                },
                "interactive": false,
                "name": "bash",
                "parent": {
                    "args": [
                        "python3",
                        "-m",
                        "rta",
                        "-n",
                        "empire_stager"
                    ],
                    "args_count": 5,
                    "command_line": "python3 -m rta -n empire_stager",
                    "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNS0xNzE3OTQxMTI0",
                    "executable": "/usr/bin/python3",
                    "group": {
                        "id": 1006,
                        "name": "admin"
                    },
                    "interactive": false,
                    "name": "python3",
                    "pid": 141205,
                    "real_group": {
                        "id": 1006,
                        "name": "admin"
                    },
                    "real_user": {
                        "id": 1005,
                        "name": "admin"
                    },
                    "start": "2024-06-09T13:52:04.27Z",
                    "supplemental_groups": [
                        {
                            "id": 4,
                            "name": "adm"
                        },
                        {
                            "id": 30,
                            "name": "dip"
                        },
                        {
                            "id": 44,
                            "name": "video"
                        },
                        {
                            "id": 46,
                            "name": "plugdev"
                        },
                        {
                            "id": 1000,
                            "name": "google-sudoers"
                        }
                    ],
                    "user": {
                        "id": 1005,
                        "name": "admin"
                    },
                    "working_directory": "/home/admin/detection-rules"
                },
                "pid": 141206,
                "previous": [
                    {
                        "args": [
                            "python3",
                            "-m",
                            "rta",
                            "-n",
                            "empire_stager"
                        ],
                        "args_count": 5,
                        "executable": "/usr/bin/python3"
                    }
                ],
                "real_group": {
                    "id": 1006,
                    "name": "admin"
                },
                "real_user": {
                    "id": 1005,
                    "name": "admin"
                },
                "session_leader": {
                    "args": [
                        "/bin/sh",
                        "-c",
                        "/tmp/rta-random-attack.sh > /tmp/rta-random.log 2>&1"
                    ],
                    "args_count": 3,
                    "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MC0xNzE3OTQxMTIx",
                    "executable": "/bin/sh",
                    "group": {
                        "id": 1006,
                        "name": "admin"
                    },
                    "interactive": false,
                    "name": "sh",
                    "pid": 141190,
                    "real_group": {
                        "id": 1006,
                        "name": "admin"
                    },
                    "real_user": {
                        "id": 1005,
                        "name": "admin"
                    },
                    "same_as_process": false,
                    "start": "2024-06-09T13:52:01.51Z",
                    "supplemental_groups": [
                        {
                            "id": 4,
                            "name": "adm"
                        },
                        {
                            "id": 30,
                            "name": "dip"
                        },
                        {
                            "id": 44,
                            "name": "video"
                        },
                        {
                            "id": 46,
                            "name": "plugdev"
                        },
                        {
                            "id": 1000,
                            "name": "google-sudoers"
                        }
                    ],
                    "user": {
                        "id": 1005,
                        "name": "admin"
                    },
                    "working_directory": "/home/admin"
                },
                "start": "2024-06-09T13:52:06.94Z",
                "supplemental_groups": [
                    {
                        "id": 4,
                        "name": "adm"
                    },
                    {
                        "id": 30,
                        "name": "dip"
                    },
                    {
                        "id": 44,
                        "name": "video"
                    },
                    {
                        "id": 46,
                        "name": "plugdev"
                    },
                    {
                        "id": 1000,
                        "name": "google-sudoers"
                    }
                ],
                "user": {
                    "id": 1005,
                    "name": "admin"
                },
                "working_directory": "/home/admin/detection-rules"
            },
            "user": {
                "Ext": {
                    "real": {
                        "id": 1005,
                        "name": "admin"
                    }
                },
                "id": 1005,
                "name": "admin"
            }
        }
    ],
    "Responses": [
        {
            "@timestamp": "2060-06-09T13:52:07.403464561Z",
            "action": {
                "action": "kill_process",
                "field": "process.entity_id",
                "state": 0
            },
            "message": "Success",
            "process": {
                "entity_id": "YyyyyyyYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNi0xNzE3OTQxMTI2",
                "name": "bash",
                "pid": 141206
            },
            "result": 0
        }
    ],
    "agent": {
        "build": {
            "original": "version: 8.13.0, compiled: Wed Mar 20 20:00:00 2024, branch: HEAD, commit: f90579240155fc17f659ed37f7864ab1194ed2ea"
        },
        "id": "abcd-513b-4526-a34a-e229a6f15dff",
        "type": "endpoint",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "elastic_security.alert",
        "namespace": "57140",
        "type": "logs"
    },
    "ecs": {
        "version": "8.10.0"
    },
    "elastic": {
        "agent": {
            "id": "abcd-513b-4526-a34a-e229a6f15dff"
        }
    },
    "elastic_agent": {
        "id": "4359bb6f-418d-48f1-abb9-fd118245ca90",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "rule_detection",
        "agent_id_status": "mismatch",
        "category": [
            "malware",
            "intrusion_detection"
        ],
        "code": "behavior",
        "created": "2024-06-09T13:52:07.402627721Z",
        "dataset": "elastic_security.alert",
        "id": "Na7UF0/g6Q++++3Y96",
        "ingested": "2025-06-24T07:51:09Z",
        "kind": "signal",
        "original": "Malicious Behavior Prevention Alert: Empire Stager Execution",
        "outcome": "success",
        "risk_score": 73,
        "sequence": 600720,
        "severity": 73,
        "type": [
            "info",
            "allowed"
        ]
    },
    "group": {
        "Ext": {
            "real": {
                "id": 1006,
                "name": "admin"
            }
        },
        "id": "1006",
        "name": "admin"
    },
    "host": {
        "architecture": "x86_64",
        "hostname": "siem-linux-release-sec-bis",
        "id": "aaaad59dd2c858c4f9b5d50c4a0e7d7",
        "ip": [
            "127.0.0.1",
            "::1",
            "89.160.20.156"
        ],
        "mac": [
            "AA-FF-AA-FF-00-02"
        ],
        "name": "siem-linux-release-sec-bis",
        "os": {
            "Ext": {
                "variant": "Debian"
            },
            "family": "debian",
            "full": "Debian 11.9",
            "kernel": "5.10.0-29-cloud-amd64 #1 SMP Debian 5.10.216-1 (2024-05-03)",
            "name": "Linux",
            "platform": "debian",
            "type": "linux",
            "version": "11.9"
        },
        "risk": {
            "calculated_level": "Critical",
            "calculated_score_norm": 98.00494
        }
    },
    "input": {
        "type": "cel"
    },
    "kibana": {
        "alert": {
            "ancestors": [
                {
                    "depth": 0,
                    "id": "f3PTBcu",
                    "index": ".ds-logs-endpoint.alerts-default-2024.05.18-002",
                    "type": "event"
                }
            ],
            "depth": 1,
            "last_detected": "2024-06-09T13:56:03.235Z",
            "original_event": {
                "action": "rule_detection",
                "agent_id_status": "verified",
                "category": [
                    "malware",
                    "intrusion_detection"
                ],
                "code": "behavior",
                "created": "2024-06-09T13:52:07.402627721Z",
                "dataset": "endpoint.alerts",
                "id": "Na7UF0/abcddd++++3Y96",
                "ingested": "2024-06-09T13:52:08Z",
                "kind": "alert",
                "module": "endpoint",
                "outcome": "success",
                "risk_score": 73,
                "sequence": 600720,
                "severity": 73,
                "type": [
                    "info",
                    "allowed"
                ]
            },
            "original_time": "2024-06-09T13:52:07.402Z",
            "reason": "malware, intrusion_detection event with process bash, parent process python3, by admin on siem-linux-release-sec-bis created high alert Malicious Behavior Prevention Alert: Empire Stager Execution.",
            "risk_score": 73,
            "rule": {
                "author": [
                    "Elastic"
                ],
                "category": "Custom Query Rule",
                "consumer": "siem",
                "created_at": "2024-04-18T11:06:23.900Z",
                "created_by": "elastic",
                "description": "Generates a detection alert each time an Elastic Endpoint Security alert is received. Enabling this rule allows you to immediately begin investigating your Endpoint alerts.",
                "enabled": true,
                "exceptions_list": [
                    {
                        "id": "endpoint_list",
                        "list_id": "endpoint_list",
                        "namespace_type": "agnostic",
                        "type": "endpoint"
                    }
                ],
                "execution": {
                    "uuid": "abcd-fda4-40dc-8586-f3d0fa908bc4"
                },
                "from": "now-10m",
                "immutable": true,
                "indices": [
                    "logs-endpoint.alerts-*"
                ],
                "interval": "5m",
                "license": "Elastic License v2",
                "max_signals": 10000,
                "name": "Malicious Behavior Prevention Alert: Empire Stager Execution",
                "parameters": {
                    "author": [
                        "Elastic"
                    ],
                    "description": "Generates a detection alert each time an Elastic Endpoint Security alert is received. Enabling this rule allows you to immediately begin investigating your Endpoint alerts.",
                    "exceptions_list": [
                        {
                            "id": "endpoint_list",
                            "list_id": "endpoint_list",
                            "namespace_type": "agnostic",
                            "type": "endpoint"
                        }
                    ],
                    "from": "now-10m",
                    "immutable": true,
                    "index": [
                        "logs-endpoint.alerts-*"
                    ],
                    "language": "kuery",
                    "license": "Elastic License v2",
                    "max_signals": 10000,
                    "query": "event.kind:alert and event.module:(endpoint and not endgame)\n",
                    "related_integrations": [
                        {
                            "package": "endpoint",
                            "version": "^8.2.0"
                        }
                    ],
                    "required_fields": [
                        {
                            "ecs": true,
                            "name": "event.kind",
                            "type": "keyword"
                        },
                        {
                            "ecs": true,
                            "name": "event.module",
                            "type": "keyword"
                        }
                    ],
                    "risk_score": 47,
                    "risk_score_mapping": [
                        {
                            "field": "event.risk_score",
                            "operator": "equals"
                        }
                    ],
                    "rule_id": "abcdef-0b5f-4c3d-8305-a268d404c306",
                    "rule_name_override": "message",
                    "setup": "## Setup\n\nThis rule is configured to generate more **Max alerts per run** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.\n\n**IMPORTANT:** The rule's **Max alerts per run** setting can be superseded by the xpack.alerting.rules.run.alerts.max Kibana config setting, which determines the maximum alerts generated by _any_ rule in the Kibana alerting framework. For example, if xpack.alerting.rules.run.alerts.max is set to 1000, this rule will still generate no more than 1000 alerts even if its own **Max alerts per run** is set higher.\n\nTo make sure this rule can generate as many alerts as it's configured in its own **Max alerts per run** setting, increase the xpack.alerting.rules.run.alerts.max system setting accordingly.\n\n**NOTE:** Changing xpack.alerting.rules.run.alerts.max is not possible in Serverless projects.",
                    "severity": "medium",
                    "severity_mapping": [
                        {
                            "field": "event.severity",
                            "operator": "equals",
                            "severity": "low",
                            "value": "21"
                        },
                        {
                            "field": "event.severity",
                            "operator": "equals",
                            "severity": "medium",
                            "value": "47"
                        },
                        {
                            "field": "event.severity",
                            "operator": "equals",
                            "severity": "high",
                            "value": "73"
                        },
                        {
                            "field": "event.severity",
                            "operator": "equals",
                            "severity": "critical",
                            "value": "99"
                        }
                    ],
                    "timestamp_override": "event.ingested",
                    "to": "now",
                    "type": "query",
                    "version": 103
                },
                "producer": "siem",
                "revision": 1,
                "risk_score": 47,
                "risk_score_mapping": [
                    {
                        "field": "event.risk_score",
                        "operator": "equals"
                    }
                ],
                "rule_id": "9a1a2dae-0b5f-4c3d-8305-a268d404c306",
                "rule_name_override": "message",
                "rule_type_id": "siem.queryRule",
                "severity": "medium",
                "severity_mapping": [
                    {
                        "field": "event.severity",
                        "operator": "equals",
                        "severity": "low",
                        "value": "21"
                    },
                    {
                        "field": "event.severity",
                        "operator": "equals",
                        "severity": "medium",
                        "value": "47"
                    },
                    {
                        "field": "event.severity",
                        "operator": "equals",
                        "severity": "high",
                        "value": "73"
                    },
                    {
                        "field": "event.severity",
                        "operator": "equals",
                        "severity": "critical",
                        "value": "99"
                    }
                ],
                "tags": [
                    "Data Source: Elastic Defend"
                ],
                "timestamp_override": "event.ingested",
                "to": "now",
                "type": "query",
                "updated_at": "2024-05-20T01:03:43.962Z",
                "updated_by": "elastic",
                "uuid": "abcd-3ea9-4695-9a1b-4af87bead73e",
                "version": 103
            },
            "severity": "high",
            "start": "2024-06-09T13:56:03.235Z",
            "status": "active",
            "url": "https://release-app/app/security/alerts/redirect/abcd?index=.alerts-security.alerts-default×tamp=2024-06-09T13:56:03.205Z",
            "uuid": "abcdef123",
            "workflow_status": "open"
        },
        "space_ids": [
            "default"
        ],
        "version": "8.14.0"
    },
    "process": {
        "Ext": {
            "ancestry": [
                "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNS0xNzE3OTQxMTI0",
                "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MS0xNzE3OTQxMTIx",
                "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MC0xNzE3OTQxMTIx",
                "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE4OS0xNzE3OTQxMTIx",
                "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTg5NS0xNzE3NzIzMDMw",
                "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTEtMTcxNzcyMzAyMQ=="
            ]
        },
        "args": [
            "/tmp/bash",
            "exec(base64.b64decode*abcdef)"
        ],
        "args_count": 2,
        "command_line": "/tmp/bash exec(base64.b64decode*abcdef)",
        "entity_id": "YYYYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNi0xNzE3OTQxMTI2",
        "entry_leader": {
            "args": [
                "/usr/sbin/cron",
                "-f"
            ],
            "args_count": 2,
            "entity_id": "YYYYYYYYYTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTg5NS0xNzE3NzIzMDMw",
            "entry_meta": {
                "type": "init"
            },
            "executable": "/usr/sbin/cron",
            "group": {
                "id": 0,
                "name": "root"
            },
            "interactive": false,
            "name": "cron",
            "parent": {
                "entity_id": "ABCDEFYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTEtMTcxNzcyMzAyMQ==",
                "pid": 1,
                "start": "2024-06-07T01:17:01.19Z"
            },
            "pid": 895,
            "real_group": {
                "id": 0,
                "name": "root"
            },
            "real_user": {
                "id": 0,
                "name": "root"
            },
            "same_as_process": false,
            "start": "2024-06-07T01:17:10.36Z",
            "user": {
                "id": 0,
                "name": "root"
            },
            "working_directory": "/var/spool/cron"
        },
        "executable": "/tmp/bash",
        "group": {
            "id": 1006,
            "name": "admin"
        },
        "group_leader": {
            "args": [
                "/bin/sh",
                "-c",
                "/tmp/rta-random-attack.sh > /tmp/rta-random.log 2>&1"
            ],
            "args_count": 3,
            "entity_id": "ABCDEFGEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MC0xNzE3OTQxMTIx",
            "executable": "/bin/sh",
            "group": {
                "id": 1006,
                "name": "admin"
            },
            "interactive": false,
            "name": "sh",
            "pid": 141190,
            "real_group": {
                "id": 1006,
                "name": "admin"
            },
            "real_user": {
                "id": 1005,
                "name": "admin"
            },
            "same_as_process": false,
            "start": "2024-06-09T13:52:01.51Z",
            "supplemental_groups": [
                {
                    "id": 4,
                    "name": "adm"
                },
                {
                    "id": 30,
                    "name": "dip"
                },
                {
                    "id": 44,
                    "name": "video"
                },
                {
                    "id": 46,
                    "name": "plugdev"
                },
                {
                    "id": 1000,
                    "name": "google-sudoers"
                }
            ],
            "user": {
                "id": 1005,
                "name": "admin"
            },
            "working_directory": "/home/admin"
        },
        "hash": {
            "md5": "ABCDf2d21a340f2b3ee534fba5b29e417",
            "sha1": "ABCDc728d069ba6239c1da751a2f31fba9b1aa",
            "sha256": "ABCD3091f6093bd9a7b308e536fbc285aeef2c5139577cc96bc594a4845f0e13"
        },
        "interactive": false,
        "name": "bash",
        "parent": {
            "args": [
                "python3",
                "-m",
                "rta",
                "-n",
                "empire_stager"
            ],
            "args_count": 5,
            "command_line": "python3 -m rta -n empire_stager",
            "entity_id": "YYYYYYYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTIwNS0xNzE3OTQxMTI0",
            "executable": "/usr/bin/python3",
            "group": {
                "id": 1006,
                "name": "admin"
            },
            "interactive": false,
            "name": "python3",
            "pid": 141205,
            "real_group": {
                "id": 1006,
                "name": "admin"
            },
            "real_user": {
                "id": 1005,
                "name": "admin"
            },
            "start": "2024-06-09T13:52:04.27Z",
            "supplemental_groups": [
                {
                    "id": 4,
                    "name": "adm"
                },
                {
                    "id": 30,
                    "name": "dip"
                },
                {
                    "id": 44,
                    "name": "video"
                },
                {
                    "id": 46,
                    "name": "plugdev"
                },
                {
                    "id": 1000,
                    "name": "google-sudoers"
                }
            ],
            "user": {
                "id": 1005,
                "name": "admin"
            },
            "working_directory": "/home/admin/detection-rules"
        },
        "pid": 141206,
        "previous": [
            {
                "args": [
                    "python3",
                    "-m",
                    "rta",
                    "-n",
                    "empire_stager"
                ],
                "args_count": 5,
                "executable": "/usr/bin/python3"
            }
        ],
        "real_group": {
            "id": 1006,
            "name": "admin"
        },
        "real_user": {
            "id": 1005,
            "name": "admin"
        },
        "session_leader": {
            "args": [
                "/bin/sh",
                "-c",
                "/tmp/rta-random-attack.sh > /tmp/rta-random.log 2>&1"
            ],
            "args_count": 3,
            "entity_id": "ABCDEYtNTEzYi00NTI2LWEzNGEtZTIyOWE2ZjE1ZGZmLTE0MTE5MC0xNzE3OTQxMTIx",
            "executable": "/bin/sh",
            "group": {
                "id": 1006,
                "name": "admin"
            },
            "interactive": false,
            "name": "sh",
            "pid": 141190,
            "real_group": {
                "id": 1006,
                "name": "admin"
            },
            "real_user": {
                "id": 1005,
                "name": "admin"
            },
            "same_as_process": false,
            "start": "2024-06-09T13:52:01.51Z",
            "supplemental_groups": [
                {
                    "id": 4,
                    "name": "adm"
                },
                {
                    "id": 30,
                    "name": "dip"
                },
                {
                    "id": 44,
                    "name": "video"
                },
                {
                    "id": 46,
                    "name": "plugdev"
                },
                {
                    "id": 1000,
                    "name": "google-sudoers"
                }
            ],
            "user": {
                "id": 1005,
                "name": "admin"
            },
            "working_directory": "/home/admin"
        },
        "start": "2024-06-09T13:52:06.94Z",
        "supplemental_groups": [
            {
                "id": 4,
                "name": "adm"
            },
            {
                "id": 30,
                "name": "dip"
            },
            {
                "id": 44,
                "name": "video"
            },
            {
                "id": 46,
                "name": "plugdev"
            },
            {
                "id": 1000,
                "name": "google-sudoers"
            }
        ],
        "user": {
            "id": 1005,
            "name": "admin"
        },
        "working_directory": "/home/admin/detection-rules"
    },
    "rule": {
        "description": "Identifies when a script interpreter executes a base64-encoded Empire stager. Empire is penetration testing software that is often utilized by attackers.",
        "id": "ABCD-82ff-4743-9e07-1c6901b1f0ea",
        "name": "Empire Stager Execution",
        "reference": [
            "https://github.com/abc/emp",
            "https://github.com/BC-abcd/emp"
        ],
        "ruleset": "production",
        "version": "1.0.29"
    },
    "source_metadata": {
        "_id": "fghiabcd",
        "_index": "abcd-1234"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "elastic_security-alert"
    ],
    "threat": [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0002",
                "name": "Execution",
                "reference": "https://attack.mitre.org/tactics/TA0002/"
            },
            "technique": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "reference": "https://attack.mitre.org/techniques/T1059/",
                    "subtechnique": [
                        {
                            "id": "T1059.004",
                            "name": "Unix Shell",
                            "reference": "https://attack.mitre.org/techniques/T1059/004/"
                        },
                        {
                            "id": "T1059.006",
                            "name": "Python",
                            "reference": "https://attack.mitre.org/techniques/T1059/006/"
                        }
                    ]
                }
            ]
        },
        {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0011",
                "name": "Command and Control",
                "reference": "https://attack.mitre.org/tactics/TA0011/"
            },
            "technique": [
                {
                    "id": "T1132",
                    "name": "Data Encoding",
                    "reference": "https://attack.mitre.org/techniques/T1132/",
                    "subtechnique": [
                        {
                            "id": "T1132.001",
                            "name": "Standard Encoding",
                            "reference": "https://attack.mitre.org/techniques/T1132/001/"
                        }
                    ]
                }
            ]
        }
    ],
    "user": {
        "Ext": {
            "real": {
                "id": 1005,
                "name": "admin"
            }
        },
        "id": "1005",
        "name": "admin",
        "risk": {
            "calculated_level": "Critical",
            "calculated_score_norm": 98.13564
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| Endpoint.policy.applied.artifacts.global.identifiers.name |  | keyword |
| Endpoint.policy.applied.artifacts.global.identifiers.sha256 |  | keyword |
| Endpoint.policy.applied.artifacts.global.snapshot |  | keyword |
| Endpoint.policy.applied.artifacts.global.update_age |  | long |
| Endpoint.policy.applied.artifacts.global.version |  | keyword |
| Endpoint.policy.applied.artifacts.user.identifiers.name |  | keyword |
| Endpoint.policy.applied.artifacts.user.identifiers.sha256 |  | keyword |
| Endpoint.policy.applied.artifacts.user.version |  | keyword |
| Events.@timestamp |  | date |
| Events._label |  | keyword |
| Events._state |  | long |
| Events.event.action |  | keyword |
| Events.event.category |  | keyword |
| Events.event.created |  | date |
| Events.event.id |  | keyword |
| Events.event.kind |  | keyword |
| Events.event.outcome |  | keyword |
| Events.event.type |  | keyword |
| Events.group.Ext.real.id |  | long |
| Events.group.Ext.real.name |  | keyword |
| Events.group.id |  | long |
| Events.group.name |  | keyword |
| Events.message |  | keyword |
| Events.process.Ext.ancestry |  | keyword |
| Events.process.args |  | keyword |
| Events.process.args_count |  | long |
| Events.process.command_line |  | keyword |
| Events.process.entity_id |  | keyword |
| Events.process.entry_leader.args |  | keyword |
| Events.process.entry_leader.args_count |  | long |
| Events.process.entry_leader.entity_id |  | keyword |
| Events.process.entry_leader.entry_meta.type |  | keyword |
| Events.process.entry_leader.executable |  | keyword |
| Events.process.entry_leader.group.id |  | long |
| Events.process.entry_leader.group.name |  | keyword |
| Events.process.entry_leader.interactive |  | boolean |
| Events.process.entry_leader.name |  | keyword |
| Events.process.entry_leader.parent.entity_id |  | keyword |
| Events.process.entry_leader.parent.pid |  | long |
| Events.process.entry_leader.parent.start |  | date |
| Events.process.entry_leader.pid |  | long |
| Events.process.entry_leader.real_group.id |  | long |
| Events.process.entry_leader.real_group.name |  | keyword |
| Events.process.entry_leader.real_user.id |  | long |
| Events.process.entry_leader.real_user.name |  | keyword |
| Events.process.entry_leader.same_as_process |  | boolean |
| Events.process.entry_leader.start |  | date |
| Events.process.entry_leader.user.id |  | long |
| Events.process.entry_leader.user.name |  | keyword |
| Events.process.entry_leader.working_directory |  | keyword |
| Events.process.executable |  | keyword |
| Events.process.group.id |  | long |
| Events.process.group.name |  | keyword |
| Events.process.group_leader.args |  | keyword |
| Events.process.group_leader.args_count |  | long |
| Events.process.group_leader.entity_id |  | keyword |
| Events.process.group_leader.executable |  | keyword |
| Events.process.group_leader.group.id |  | long |
| Events.process.group_leader.group.name |  | keyword |
| Events.process.group_leader.interactive |  | boolean |
| Events.process.group_leader.name |  | keyword |
| Events.process.group_leader.pid |  | long |
| Events.process.group_leader.real_group.id |  | long |
| Events.process.group_leader.real_group.name |  | keyword |
| Events.process.group_leader.real_user.id |  | long |
| Events.process.group_leader.real_user.name |  | keyword |
| Events.process.group_leader.same_as_process |  | boolean |
| Events.process.group_leader.start |  | date |
| Events.process.group_leader.supplemental_groups.id |  | long |
| Events.process.group_leader.supplemental_groups.name |  | keyword |
| Events.process.group_leader.user.id |  | long |
| Events.process.group_leader.user.name |  | keyword |
| Events.process.group_leader.working_directory |  | keyword |
| Events.process.hash.md5 |  | keyword |
| Events.process.hash.sha1 |  | keyword |
| Events.process.hash.sha256 |  | keyword |
| Events.process.interactive |  | boolean |
| Events.process.name |  | keyword |
| Events.process.parent.args |  | keyword |
| Events.process.parent.args_count |  | long |
| Events.process.parent.command_line |  | keyword |
| Events.process.parent.entity_id |  | keyword |
| Events.process.parent.executable |  | keyword |
| Events.process.parent.group.id |  | long |
| Events.process.parent.group.name |  | keyword |
| Events.process.parent.interactive |  | boolean |
| Events.process.parent.name |  | keyword |
| Events.process.parent.pid |  | long |
| Events.process.parent.real_group.id |  | long |
| Events.process.parent.real_group.name |  | keyword |
| Events.process.parent.real_user.id |  | long |
| Events.process.parent.real_user.name |  | keyword |
| Events.process.parent.start |  | keyword |
| Events.process.parent.supplemental_groups.id |  | long |
| Events.process.parent.supplemental_groups.name |  | keyword |
| Events.process.parent.user.id |  | long |
| Events.process.parent.user.name |  | keyword |
| Events.process.parent.working_directory |  | keyword |
| Events.process.pid |  | long |
| Events.process.previous.args |  | keyword |
| Events.process.previous.args_count |  | long |
| Events.process.previous.executable |  | keyword |
| Events.process.real_group.id |  | long |
| Events.process.real_group.name |  | keyword |
| Events.process.real_user.id |  | long |
| Events.process.real_user.name |  | keyword |
| Events.process.session_leader.args |  | keyword |
| Events.process.session_leader.args_count |  | long |
| Events.process.session_leader.entity_id |  | keyword |
| Events.process.session_leader.executable |  | keyword |
| Events.process.session_leader.group.id |  | long |
| Events.process.session_leader.group.name |  | keyword |
| Events.process.session_leader.interactive |  | boolean |
| Events.process.session_leader.name |  | keyword |
| Events.process.session_leader.pid |  | long |
| Events.process.session_leader.real_group.id |  | long |
| Events.process.session_leader.real_group.name |  | keyword |
| Events.process.session_leader.real_user.id |  | long |
| Events.process.session_leader.real_user.name |  | keyword |
| Events.process.session_leader.same_as_process |  | boolean |
| Events.process.session_leader.start |  | keyword |
| Events.process.session_leader.supplemental_groups.id |  | long |
| Events.process.session_leader.supplemental_groups.name |  | keyword |
| Events.process.session_leader.user.id |  | long |
| Events.process.session_leader.user.name |  | keyword |
| Events.process.session_leader.working_directory |  | keyword |
| Events.process.start |  | keyword |
| Events.process.supplemental_groups.id |  | long |
| Events.process.supplemental_groups.name |  | keyword |
| Events.process.user.id |  | long |
| Events.process.user.name |  | keyword |
| Events.process.working_directory |  | keyword |
| Events.user.Ext.real.id |  | long |
| Events.user.Ext.real.name |  | keyword |
| Events.user.id |  | long |
| Events.user.name |  | keyword |
| Responses.@timestamp |  | date |
| Responses.action.action |  | keyword |
| Responses.action.field |  | keyword |
| Responses.action.state |  | long |
| Responses.message |  | keyword |
| Responses.process.entity_id |  | keyword |
| Responses.process.name |  | keyword |
| Responses.process.pid |  | long |
| Responses.result |  | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elastic.agent.id |  | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| group.Ext.real.id |  | long |
| group.Ext.real.name |  | keyword |
| input.type | Type of filebeat input. | keyword |
| kibana.alert.ancestors.depth |  | long |
| kibana.alert.ancestors.id |  | keyword |
| kibana.alert.ancestors.index |  | keyword |
| kibana.alert.ancestors.type |  | keyword |
| kibana.alert.depth |  | long |
| kibana.alert.last_detected |  | keyword |
| kibana.alert.original_event.action |  | keyword |
| kibana.alert.original_event.agent_id_status |  | keyword |
| kibana.alert.original_event.category |  | keyword |
| kibana.alert.original_event.code |  | keyword |
| kibana.alert.original_event.created |  | keyword |
| kibana.alert.original_event.dataset |  | keyword |
| kibana.alert.original_event.id |  | keyword |
| kibana.alert.original_event.ingested |  | keyword |
| kibana.alert.original_event.kind |  | keyword |
| kibana.alert.original_event.module |  | keyword |
| kibana.alert.original_event.outcome |  | keyword |
| kibana.alert.original_event.risk_score |  | long |
| kibana.alert.original_event.sequence |  | long |
| kibana.alert.original_event.severity |  | long |
| kibana.alert.original_event.type |  | keyword |
| kibana.alert.original_time |  | keyword |
| kibana.alert.reason |  | keyword |
| kibana.alert.risk_score |  | long |
| kibana.alert.rule.author |  | keyword |
| kibana.alert.rule.category |  | keyword |
| kibana.alert.rule.consumer |  | keyword |
| kibana.alert.rule.created_at |  | keyword |
| kibana.alert.rule.created_by |  | keyword |
| kibana.alert.rule.description |  | keyword |
| kibana.alert.rule.enabled |  | boolean |
| kibana.alert.rule.exceptions_list.id |  | keyword |
| kibana.alert.rule.exceptions_list.list_id |  | keyword |
| kibana.alert.rule.exceptions_list.namespace_type |  | keyword |
| kibana.alert.rule.exceptions_list.type |  | keyword |
| kibana.alert.rule.execution.uuid |  | keyword |
| kibana.alert.rule.from |  | keyword |
| kibana.alert.rule.immutable |  | boolean |
| kibana.alert.rule.indices |  | keyword |
| kibana.alert.rule.interval |  | keyword |
| kibana.alert.rule.license |  | keyword |
| kibana.alert.rule.max_signals |  | long |
| kibana.alert.rule.name |  | keyword |
| kibana.alert.rule.parameters.author |  | keyword |
| kibana.alert.rule.parameters.description |  | keyword |
| kibana.alert.rule.parameters.exceptions_list.id |  | keyword |
| kibana.alert.rule.parameters.exceptions_list.list_id |  | keyword |
| kibana.alert.rule.parameters.exceptions_list.namespace_type |  | keyword |
| kibana.alert.rule.parameters.exceptions_list.type |  | keyword |
| kibana.alert.rule.parameters.from |  | keyword |
| kibana.alert.rule.parameters.immutable |  | boolean |
| kibana.alert.rule.parameters.index |  | keyword |
| kibana.alert.rule.parameters.language |  | keyword |
| kibana.alert.rule.parameters.license |  | keyword |
| kibana.alert.rule.parameters.max_signals |  | long |
| kibana.alert.rule.parameters.query |  | keyword |
| kibana.alert.rule.parameters.related_integrations.package |  | keyword |
| kibana.alert.rule.parameters.related_integrations.version |  | keyword |
| kibana.alert.rule.parameters.required_fields.ecs |  | boolean |
| kibana.alert.rule.parameters.required_fields.name |  | keyword |
| kibana.alert.rule.parameters.required_fields.type |  | keyword |
| kibana.alert.rule.parameters.risk_score |  | long |
| kibana.alert.rule.parameters.risk_score_mapping.field |  | keyword |
| kibana.alert.rule.parameters.risk_score_mapping.operator |  | keyword |
| kibana.alert.rule.parameters.rule_id |  | keyword |
| kibana.alert.rule.parameters.rule_name_override |  | keyword |
| kibana.alert.rule.parameters.setup |  | keyword |
| kibana.alert.rule.parameters.severity |  | keyword |
| kibana.alert.rule.parameters.severity_mapping.field |  | keyword |
| kibana.alert.rule.parameters.severity_mapping.operator |  | keyword |
| kibana.alert.rule.parameters.severity_mapping.severity |  | keyword |
| kibana.alert.rule.parameters.severity_mapping.value |  | keyword |
| kibana.alert.rule.parameters.timestamp_override |  | keyword |
| kibana.alert.rule.parameters.to |  | keyword |
| kibana.alert.rule.parameters.type |  | keyword |
| kibana.alert.rule.parameters.version |  | long |
| kibana.alert.rule.producer |  | keyword |
| kibana.alert.rule.revision |  | long |
| kibana.alert.rule.risk_score |  | long |
| kibana.alert.rule.risk_score_mapping.field |  | keyword |
| kibana.alert.rule.risk_score_mapping.operator |  | keyword |
| kibana.alert.rule.rule_id |  | keyword |
| kibana.alert.rule.rule_name_override |  | keyword |
| kibana.alert.rule.rule_type_id |  | keyword |
| kibana.alert.rule.severity |  | keyword |
| kibana.alert.rule.severity_mapping.field |  | keyword |
| kibana.alert.rule.severity_mapping.operator |  | keyword |
| kibana.alert.rule.severity_mapping.severity |  | keyword |
| kibana.alert.rule.severity_mapping.value |  | keyword |
| kibana.alert.rule.tags |  | keyword |
| kibana.alert.rule.timestamp_override |  | keyword |
| kibana.alert.rule.to |  | keyword |
| kibana.alert.rule.type |  | keyword |
| kibana.alert.rule.updated_at |  | keyword |
| kibana.alert.rule.updated_by |  | keyword |
| kibana.alert.rule.uuid |  | keyword |
| kibana.alert.rule.version |  | long |
| kibana.alert.severity |  | keyword |
| kibana.alert.start |  | keyword |
| kibana.alert.status |  | keyword |
| kibana.alert.url |  | keyword |
| kibana.alert.uuid |  | keyword |
| kibana.alert.workflow_status |  | keyword |
| kibana.space_ids |  | keyword |
| kibana.version |  | keyword |
| log.offset | Log offset. | long |
| process.Ext.ancestry |  | keyword |
| process.args |  | keyword |
| process.args_count |  | long |
| process.command_line |  | keyword |
| process.entity_id |  | keyword |
| process.entry_leader.args |  | keyword |
| process.entry_leader.args_count |  | long |
| process.entry_leader.entity_id |  | keyword |
| process.entry_leader.entry_meta.type |  | keyword |
| process.entry_leader.executable |  | keyword |
| process.entry_leader.group.id |  | long |
| process.entry_leader.group.name |  | keyword |
| process.entry_leader.interactive |  | boolean |
| process.entry_leader.name |  | keyword |
| process.entry_leader.parent.entity_id |  | keyword |
| process.entry_leader.parent.pid |  | long |
| process.entry_leader.parent.start |  | keyword |
| process.entry_leader.pid |  | long |
| process.entry_leader.real_group.id |  | long |
| process.entry_leader.real_group.name |  | keyword |
| process.entry_leader.real_user.id |  | long |
| process.entry_leader.real_user.name |  | keyword |
| process.entry_leader.same_as_process |  | boolean |
| process.entry_leader.start |  | keyword |
| process.entry_leader.user.id |  | long |
| process.entry_leader.user.name |  | keyword |
| process.entry_leader.working_directory |  | keyword |
| process.executable |  | keyword |
| process.group.id |  | long |
| process.group.name |  | keyword |
| process.group_leader.args |  | keyword |
| process.group_leader.args_count |  | long |
| process.group_leader.entity_id |  | keyword |
| process.group_leader.executable |  | keyword |
| process.group_leader.group.id |  | long |
| process.group_leader.group.name |  | keyword |
| process.group_leader.interactive |  | boolean |
| process.group_leader.name |  | keyword |
| process.group_leader.pid |  | long |
| process.group_leader.real_group.id |  | long |
| process.group_leader.real_group.name |  | keyword |
| process.group_leader.real_user.id |  | long |
| process.group_leader.real_user.name |  | keyword |
| process.group_leader.same_as_process |  | boolean |
| process.group_leader.start |  | keyword |
| process.group_leader.supplemental_groups.id |  | long |
| process.group_leader.supplemental_groups.name |  | keyword |
| process.group_leader.user.id |  | long |
| process.group_leader.user.name |  | keyword |
| process.group_leader.working_directory |  | keyword |
| process.hash.md5 |  | keyword |
| process.hash.sha1 |  | keyword |
| process.hash.sha256 |  | keyword |
| process.interactive |  | boolean |
| process.name |  | keyword |
| process.parent.args |  | keyword |
| process.parent.args_count |  | long |
| process.parent.command_line |  | keyword |
| process.parent.entity_id |  | keyword |
| process.parent.executable |  | keyword |
| process.parent.group.id |  | long |
| process.parent.group.name |  | keyword |
| process.parent.interactive |  | boolean |
| process.parent.name |  | keyword |
| process.parent.pid |  | long |
| process.parent.real_group.id |  | long |
| process.parent.real_group.name |  | keyword |
| process.parent.real_user.id |  | long |
| process.parent.real_user.name |  | keyword |
| process.parent.start |  | keyword |
| process.parent.supplemental_groups.id |  | long |
| process.parent.supplemental_groups.name |  | keyword |
| process.parent.user.id |  | long |
| process.parent.user.name |  | keyword |
| process.parent.working_directory |  | keyword |
| process.pid |  | long |
| process.previous.args |  | keyword |
| process.previous.args_count |  | long |
| process.previous.executable |  | keyword |
| process.real_group.id |  | long |
| process.real_group.name |  | keyword |
| process.real_user.id |  | long |
| process.real_user.name |  | keyword |
| process.session_leader.args |  | keyword |
| process.session_leader.args_count |  | long |
| process.session_leader.entity_id |  | keyword |
| process.session_leader.executable |  | keyword |
| process.session_leader.group.id |  | long |
| process.session_leader.group.name |  | keyword |
| process.session_leader.interactive |  | boolean |
| process.session_leader.name |  | keyword |
| process.session_leader.pid |  | long |
| process.session_leader.real_group.id |  | long |
| process.session_leader.real_group.name |  | keyword |
| process.session_leader.real_user.id |  | long |
| process.session_leader.real_user.name |  | keyword |
| process.session_leader.same_as_process |  | boolean |
| process.session_leader.start |  | keyword |
| process.session_leader.supplemental_groups.id |  | long |
| process.session_leader.supplemental_groups.name |  | keyword |
| process.session_leader.user.id |  | long |
| process.session_leader.user.name |  | keyword |
| process.session_leader.working_directory |  | keyword |
| process.start |  | keyword |
| process.supplemental_groups.id |  | long |
| process.supplemental_groups.name |  | keyword |
| process.user.id |  | long |
| process.user.name |  | keyword |
| process.working_directory |  | keyword |
| sort |  | long |
| source_metadata._id |  | keyword |
| source_metadata._index |  | keyword |
| threat.tactic.id |  | keyword |
| threat.tactic.name |  | keyword |
| threat.tactic.reference |  | keyword |
| threat.technique.id |  | keyword |
| threat.technique.name |  | keyword |
| threat.technique.reference |  | keyword |
| threat.technique.subtechnique.id |  | keyword |
| threat.technique.subtechnique.name |  | keyword |
| threat.technique.subtechnique.reference |  | keyword |
| user.Ext.real.id |  | long |
| user.Ext.real.name |  | keyword |
