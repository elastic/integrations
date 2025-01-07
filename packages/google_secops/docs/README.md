# Google SecOps

[Google SecOps](https://cloud.google.com/chronicle/docs/secops/secops-overview) is a cloud-based service designed for enterprises to retain, analyze, and search large volumes of security and network telemetry. It normalizes, indexes, and correlates data to detect threats, investigate their scope and cause, and provide remediation through prebuilt integrations. The platform enables security analysts to examine aggregated security information, search across domains, and mitigate threats throughout their lifecycle.

The Google SecOps integration collects alerts using the [REST API](https://cloud.google.com/chronicle/docs/reference/search-api#udmsearch).

## Compatibility

This module has been tested against the Google SecOps version **v1**.

## Data streams

This integration collects the following logs:

- **[Alerts](https://cloud.google.com/chronicle/docs/reference/udm-field-list)** - This method enables users to retrieve alerts from Google SecOps.

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Setup

### To collect data from the Google SecOps API:

   - Create Google SecOps service account [Steps to create](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount).
   - Permissions required for Service Account: 
      - chronicle.events.udmSearch
   - **Chronicle API** must be enabled.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/chronicle-backstory`

Once Service Account credentials are downloaded as a JSON file, then the integration can be setup to collect data.

If installing in GCP-Cloud Environment, No need to provide any credentials and make sure the account linked with the VM has all the required IAM permissions. Steps to [Set up Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Google SecOps`.
3. Select the "Google SecOps" integration from the search results.
4. Select "Add Google SecOps" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Credentials Type, and Credentials, to enable data collection.
6. Select "Save and continue" to save the integration.

**Note**: The default URL is `https://backstory.googleapis.com`, but this may vary depending on your region. Please refer to the [Documentation](https://cloud.google.com/chronicle/docs/reference/search-api#regional_endpoints) to find the correct URL for your region.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2024-12-20T11:45:00.000Z",
    "agent": {
        "ephemeral_id": "0d1a5733-f16f-4ae9-b974-c0b38f4055d6",
        "id": "c71b55b2-5100-4826-8c27-80e76b826c97",
        "name": "elastic-agent-34472",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "data_stream": {
        "dataset": "google_secops.alert",
        "namespace": "38028",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": [
                15169
            ],
            "organization": {
                "name": [
                    "TargetISP Corp"
                ]
            }
        },
        "bytes": 2048,
        "domain": "target-server",
        "geo": {
            "country_name": [
                "US"
            ],
            "location": [
                {
                    "lat": 51.0950244,
                    "lon": 4.4477809
                }
            ],
            "region_name": [
                "California"
            ]
        },
        "ip": [
            "10.1.1.100",
            "192.168.50.1"
        ],
        "port": 5432,
        "user": {
            "email": [
                "target.user@example.com"
            ],
            "group": {
                "id": [
                    "target-admins"
                ]
            },
            "id": "user-1234",
            "name": "Target User"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c71b55b2-5100-4826-8c27-80e76b826c97",
        "snapshot": false,
        "version": "8.15.0"
    },
    "email": {
        "from": {
            "address": [
                "admin@example.com"
            ]
        },
        "message_id": [
            "mail-12345"
        ],
        "subject": [
            "Security Alert"
        ],
        "to": {
            "address": [
                "user@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "google_secops.alert",
        "id": "000000001234567bbf000cacaf111eaa4400ebdb000000001400000000000000",
        "ingested": "2025-01-07T12:24:53Z",
        "kind": "alert",
        "original": "{\"name\":\"000000001234567bbf000cacaf111eaa4400ebdb000000001400000000000000\",\"udm\":{\"about\":[{\"administrativeDomain\":\"example.com\",\"file\":{\"fullPath\":\"/var/log/syslog\",\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"},\"group\":{\"groupDisplayName\":\"wheel\"},\"labels\":[{\"key\":\"compliances_id\",\"value\":\"A.8.5\"}],\"namespace\":\"security\",\"resource\":{\"id\":\"12345\",\"name\":\"WebServer\",\"productObjectId\":\"prod-67890\",\"resourceType\":\"virtualMachine\",\"type\":\"compute\"},\"url\":\"https://example.com/resource/12345\",\"user\":{\"attribute\":{\"roles\":[{\"name\":\"Administrator\"}]},\"emailAddresses\":[\"user@example.com\"],\"groupIdentifiers\":[\"group-1\"],\"userDisplayName\":\"John Doe\",\"userid\":\"user123\"}}],\"additional\":{},\"extensions\":{\"auth\":{\"authDetails\":\"Login successful\",\"mechanism\":[\"OAuth2\"],\"type\":\"authentication\"},\"vulns\":{\"vulnerabilities\":[{\"about\":{\"labels\":[{\"key\":\"vulnType\",\"value\":\"critical\"}]},\"cveId\":\"CVE-2023-12345\",\"cvssBaseScore\":9.8,\"cvssVector\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"}]}},\"intermediary\":[{\"application\":\"proxy-server\",\"hostname\":\"proxy01.example.com\",\"ip\":[\"192.168.0.1\",\"175.16.199.2\"],\"location\":{\"countryOrRegion\":\"US\",\"regionCoordinates\":{\"latitude\":51.0950244,\"longitude\":4.4477809}},\"namespace\":\"intermediary-namespace-1\",\"network\":{\"receivedBytes\":1048576,\"sentBytes\":524288},\"port\":8080,\"resource\":{\"attribute\":{\"labels\":[{\"key\":\"role\",\"value\":\"gateway\"},{\"key\":\"environment\",\"value\":\"staging\"}]}}}],\"metadata\":{\"baseLabels\":{\"allowScopedAccess\":true,\"logTypes\":[\"audit\"]},\"collectedTimestamp\":\"2024-12-20T12:00:00Z\",\"description\":\"Example log entry for demonstration\",\"enrichmentLabels\":{\"allowScopedAccess\":false,\"logTypes\":[\"security\"]},\"enrichmentState\":\"complete\",\"eventTimestamp\":\"2024-12-20T11:45:00Z\",\"eventType\":\"access\",\"id\":\"log-12345\",\"ingestedTimestamp\":\"2024-12-20T12:01:00Z\",\"ingestionLabels\":[{\"key\":\"source\",\"value\":\"application\"}],\"logType\":\"security\",\"productDeploymentId\":\"deployment-1\",\"productEventType\":\"login\",\"productLogId\":\"log-67890\",\"productName\":\"SecurityApp\",\"productVersion\":\"1.0\",\"urlBackToProduct\":\"https://example.com/log/12345\",\"vendorName\":\"ExampleVendor\"},\"network\":{\"email\":{\"from\":\"admin@example.com\",\"mailId\":\"mail-12345\",\"subject\":[\"Security Alert\"],\"to\":[\"user@example.com\"]},\"http\":{\"parsedUserAgent\":{\"annotation\":[{\"key\":\"deviceType\",\"value\":\"mobile\"}],\"browser\":\"Chrome\",\"browserEngineVersion\":\"110.0\",\"browserVersion\":\"110.0.5481.77\",\"device\":\"Pixel\",\"deviceVersion\":\"6\",\"family\":\"Android\",\"os\":\"Android\",\"osVariant\":\"12\",\"platform\":\"mobile\",\"subFamily\":\"Pixel\"},\"userAgent\":\"Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Mobile Safari/537.36\"},\"ipProtocol\":\"TCP\",\"receivedBytes\":2048,\"sentBytes\":1024,\"sessionId\":\"session-12345\",\"tls\":{\"cipher\":\"AES_128_GCM\",\"version\":\"TLSv1.3\"}},\"principal\":{\"application\":\"web-portal\",\"asset\":{\"assetId\":\"asset-12345\",\"attribute\":{\"cloud\":{\"availabilityZone\":\"us-east-1a\",\"environment\":\"production\"},\"creationTime\":\"2024-12-23T10:15:30Z\",\"labels\":[{\"key\":\"owner\",\"value\":\"team-security\"},{\"key\":\"project\",\"value\":\"secops\"}]},\"category\":\"server\",\"deploymentStatus\":\"active\",\"hardware\":[{\"cpuPlatform\":\"Intel Xeon\",\"model\":\"x86_64\",\"serialNumber\":\"SN12345XYZ\"}],\"hostname\":\"sec-server01.example.com\",\"ip\":\"192.168.1.10\",\"lastBootTime\":\"2024-12-20T08:00:00Z\",\"location\":{\"name\":\"Data Center 1\"},\"natIp\":[\"1.128.0.0\"],\"productObjectId\":\"poid-67890\",\"software\":[{\"version\":\"v1.2.3\"}]},\"assetId\":\"asset-12345\",\"group\":{\"groupDisplayName\":\"IT Security Group\"},\"hostname\":\"sec-client01.example.com\",\"ip\":[\"10.0.0.1\"],\"ipGeoArtifact\":[{\"ip\":\"1.128.0.1\",\"location\":{\"countryOrRegion\":\"US\",\"regionCoordinates\":{\"latitude\":51.0950244,\"longitude\":4.4477809},\"regionLatitude\":40.7128,\"regionLongitude\":-74.006,\"state\":\"New York\"},\"network\":{\"asn\":\"12345\",\"carrierName\":\"ISP-Example\",\"dnsDomain\":\"example.com\",\"organizationName\":\"Example Corp\"}}],\"labels\":[{\"key\":\"env\",\"value\":\"production\"}],\"location\":{\"city\":\"New York\",\"countryOrRegion\":\"US\",\"name\":\"Corporate Office\",\"regionCoordinates\":{\"latitude\":51.0950244,\"longitude\":4.4477809},\"regionLatitude\":40.7128,\"regionLongitude\":-74.006,\"state\":\"New York\"},\"namespace\":\"principal-namespace\",\"natIp\":[\"175.16.199.3\"],\"network\":{\"receivedBytes\":5120,\"sentBytes\":2048},\"platform\":\"Windows 10\",\"port\":443,\"process\":{\"commandLine\":\"C:\\\\Program Files\\\\App\\\\app.exe --arg1\",\"file\":{\"fullPath\":\"C:\\\\Program Files\\\\App\\\\app.exe\",\"md5\":\"9e107d9d372bb6826bd81d3542a419d6\",\"sha1\":\"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\",\"sha256\":\"d7a8fbb307d7809469ca9abcb0082e4ff7bcd8d97ad8b84b76329ac5d89d6bce\"},\"parentProcess\":{\"file\":{\"fullPath\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"},\"pid\":4567},\"pid\":7890},\"processAncestors\":[{\"file\":{\"fullPath\":\"C:\\\\Windows\\\\explorer.exe\"},\"pid\":1234}],\"resource\":{\"name\":\"resource-name\",\"productObjectId\":\"res-prod-789\",\"resourceSubtype\":\"web-app\",\"type\":\"application\"},\"securityResult\":[{\"about\":{\"labels\":[{\"key\":\"threat\",\"value\":\"malware\"}]},\"detectionFields\":[{\"key\":\"file\",\"value\":\"malicious.exe\"}]}],\"user\":{\"accountType\":\"admin\",\"attribute\":{\"cloud\":{\"environment\":\"corporate\"},\"creationTime\":\"2023-01-15T10:00:00Z\",\"labels\":[{\"key\":\"role\",\"value\":\"security-admin\"}],\"permissions\":[{\"name\":\"read\"},{\"name\":\"write\"}],\"roles\":[{\"name\":\"security-analyst\",\"type\":\"primary\"}]},\"emailAddresses\":[\"admin@example.com\"],\"groupIdentifiers\":[\"group-id-123\"],\"productObjectId\":\"user-prod-123\",\"userDisplayName\":\"John Doe\",\"userid\":\"jdoe\",\"windowsSid\":\"S-1-5-21-123456789-1234567890-1234567890-1001\"}},\"securityResult\":[{\"about\":{\"labels\":[{\"key\":\"source\",\"value\":\"SIEM\"},{\"key\":\"threatType\",\"value\":\"malware\"}],\"namespace\":\"security-namespace-1\",\"objectReference\":{\"id\":\"malware-incident-12345\"},\"resource\":{\"name\":\"endpoint01\"},\"user\":{\"attribute\":{\"roles\":[{\"name\":\"Admin\"},{\"name\":\"Security Analyst\"}]},\"emailAddresses\":[\"admin@example.com\",\"security@example.com\"]}},\"action\":[\"isolate\",\"notify\"],\"actionDetails\":\"Endpoint isolated and security team notified\",\"alertState\":\"active\",\"category\":[\"endpoint\",\"malware\"],\"categoryDetails\":[\"Critical malware detected on endpoint01\"],\"description\":\"Malware detected on endpoint. Immediate action required.\",\"detectionFields\":[{\"key\":\"hash\",\"value\":\"e3b0c44298fc1c149afbf4c8996fb924\"},{\"key\":\"filePath\",\"value\":\"/var/tmp/malicious.exe\"}],\"outcomes\":[{\"key\":\"isolationStatus\",\"value\":\"success\"},{\"key\":\"notificationStatus\",\"value\":\"sent\"}],\"priority\":\"high\",\"priorityDetails\":\"Critical threat to organization security\",\"ruleName\":\"Critical Malware Detection\",\"severity\":\"critical\",\"summary\":\"Critical malware detected on endpoint01; actions taken: isolation and notification\",\"urlBackToProduct\":\"https://securityportal.example.com/incidents/malware-incident-12345\"}],\"src\":{\"ip\":[\"175.16.199.0\",\"175.16.199.1\"],\"namespace\":\"source-namespace-1\",\"port\":443},\"target\":{\"administrativeDomain\":\"example.com\",\"application\":\"TargetApp\",\"asset\":{\"hostname\":\"target-endpoint01\"},\"cloud\":{\"project\":{\"name\":\"Target Cloud Project\"}},\"file\":{\"fullPath\":\"/etc/target.conf\",\"sha256\":\"d2d2d2d2e3b0c44298fc1c149afbf4c8996fb924\"},\"group\":{\"groupDisplayName\":\"TargetGroup\"},\"hostname\":\"target-server\",\"ip\":[\"10.1.1.100\",\"192.168.50.1\"],\"ipGeoArtifact\":[{\"ip\":\"10.1.1.100\",\"location\":{\"countryOrRegion\":\"US\",\"regionCoordinates\":{\"latitude\":51.0950244,\"longitude\":4.4477809},\"regionLatitude\":38.5454,\"regionLongitude\":-120.7394,\"state\":\"California\"},\"network\":{\"asn\":\"15169\",\"carrierName\":\"TargetISP\",\"dnsDomain\":\"targetisp.com\",\"organizationName\":\"TargetISP Corp\"}}],\"labels\":[{\"key\":\"environment\",\"value\":\"production\"},{\"key\":\"role\",\"value\":\"database-server\"}],\"location\":{\"countryOrRegion\":\"US\",\"name\":\"Target Datacenter\",\"regionCoordinates\":{\"latitude\":51.0950244,\"longitude\":4.4477809},\"regionLatitude\":38.5454,\"regionLongitude\":-120.7394,\"state\":\"California\"},\"namespace\":\"target-namespace\",\"network\":{\"sentBytes\":15000},\"port\":5432,\"process\":{\"file\":{\"fullPath\":\"/usr/bin/target-process\"}},\"resource\":{\"attribute\":{\"cloud\":{\"availabilityZone\":\"us-central1-a\"},\"labels\":[{\"key\":\"team\",\"value\":\"DevOps\"},{\"key\":\"priority\",\"value\":\"high\"}],\"permissions\":[{\"name\":\"read\"},{\"name\":\"write\"}]},\"name\":\"TargetResource01\",\"productObjectId\":\"resource-obj-12345\",\"resourceType\":\"database\",\"type\":\"Compute\"},\"resourceAncestors\":[{\"attribute\":{\"labels\":[{\"key\":\"owner\",\"value\":\"InfrastructureTeam\"},{\"key\":\"classification\",\"value\":\"confidential\"}],\"permissions\":[{\"name\":\"admin\"}]},\"name\":\"ParentResource01\",\"productObjectId\":\"parent-obj-67890\",\"resourceSubtype\":\"Cluster\",\"resourceType\":\"Kubernetes\"}],\"user\":{\"attribute\":{\"permissions\":[{\"name\":\"execute\"},{\"name\":\"monitor\"}]},\"emailAddresses\":[\"target.user@example.com\"],\"groupIdentifiers\":[\"target-admins\"],\"userDisplayName\":\"Target User\",\"userid\":\"user-1234\",\"windowsSid\":\"S-1-5-21-3623811015-3361044348-30300820-1013\"}}}}"
    },
    "file": {
        "hash": {
            "md5": "9e107d9d372bb6826bd81d3542a419d6",
            "sha1": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "sha256": "d7a8fbb307d7809469ca9abcb0082e4ff7bcd8d97ad8b84b76329ac5d89d6bce"
        },
        "path": "C:\\Program Files\\App\\app.exe"
    },
    "google_secops": {
        "alert": {
            "name": "000000001234567bbf000cacaf111eaa4400ebdb000000001400000000000000",
            "udm": {
                "about": [
                    {
                        "administrativeDomain": "example.com",
                        "file": {
                            "fullPath": "/var/log/syslog",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        },
                        "group": {
                            "groupDisplayName": "wheel"
                        },
                        "labels": [
                            {
                                "key": "compliances_id",
                                "value": "A.8.5"
                            }
                        ],
                        "namespace": "security",
                        "resource": {
                            "id": "12345",
                            "name": "WebServer",
                            "productObjectId": "prod-67890",
                            "resourceType": "virtualMachine",
                            "type": "compute"
                        },
                        "url": "https://example.com/resource/12345",
                        "user": {
                            "attribute": {
                                "roles": [
                                    {
                                        "name": "Administrator"
                                    }
                                ]
                            },
                            "emailAddresses": [
                                "user@example.com"
                            ],
                            "groupIdentifiers": [
                                "group-1"
                            ],
                            "userDisplayName": "John Doe",
                            "userid": "user123"
                        }
                    }
                ],
                "extensions": {
                    "auth": {
                        "authDetails": "Login successful",
                        "mechanism": [
                            "OAuth2"
                        ],
                        "type": "authentication"
                    },
                    "vulns": {
                        "vulnerabilities": [
                            {
                                "about": {
                                    "labels": [
                                        {
                                            "key": "vulnType",
                                            "value": "critical"
                                        }
                                    ]
                                },
                                "cveId": "CVE-2023-12345",
                                "cvssBaseScore": 9.8,
                                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        ]
                    }
                },
                "intermediary": [
                    {
                        "application": "proxy-server",
                        "hostname": "proxy01.example.com",
                        "ip": [
                            "192.168.0.1",
                            "175.16.199.2"
                        ],
                        "location": {
                            "countryOrRegion": "US",
                            "regionCoordinates": {
                                "latitude": 51.0950244,
                                "longitude": 4.4477809
                            }
                        },
                        "namespace": "intermediary-namespace-1",
                        "network": {
                            "receivedBytes": 1048576,
                            "sentBytes": 524288
                        },
                        "port": 8080,
                        "resource": {
                            "attribute": {
                                "labels": [
                                    {
                                        "key": "role",
                                        "value": "gateway"
                                    },
                                    {
                                        "key": "environment",
                                        "value": "staging"
                                    }
                                ]
                            }
                        }
                    }
                ],
                "metadata": {
                    "baseLabels": {
                        "allowScopedAccess": true,
                        "logTypes": [
                            "audit"
                        ]
                    },
                    "collectedTimestamp": "2024-12-20T12:00:00.000Z",
                    "description": "Example log entry for demonstration",
                    "enrichmentLabels": {
                        "allowScopedAccess": false,
                        "logTypes": [
                            "security"
                        ]
                    },
                    "enrichmentState": "complete",
                    "eventTimestamp": "2024-12-20T11:45:00.000Z",
                    "eventType": "access",
                    "id": "log-12345",
                    "ingestedTimestamp": "2024-12-20T12:01:00.000Z",
                    "ingestionLabels": [
                        {
                            "key": "source",
                            "value": "application"
                        }
                    ],
                    "logType": "security",
                    "productDeploymentId": "deployment-1",
                    "productEventType": "login",
                    "productLogId": "log-67890",
                    "productName": "SecurityApp",
                    "productVersion": "1.0",
                    "urlBackToProduct": "https://example.com/log/12345",
                    "vendorName": "ExampleVendor"
                },
                "network": {
                    "email": {
                        "from": "admin@example.com",
                        "mailId": "mail-12345",
                        "subject": [
                            "Security Alert"
                        ],
                        "to": [
                            "user@example.com"
                        ]
                    },
                    "http": {
                        "parsedUserAgent": {
                            "annotation": [
                                {
                                    "key": "deviceType",
                                    "value": "mobile"
                                }
                            ],
                            "browser": "Chrome",
                            "browserEngineVersion": "110.0",
                            "browserVersion": "110.0.5481.77",
                            "device": "Pixel",
                            "deviceVersion": "6",
                            "family": "Android",
                            "os": "Android",
                            "osVariant": "12",
                            "platform": "mobile",
                            "subFamily": "Pixel"
                        },
                        "userAgent": "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Mobile Safari/537.36"
                    },
                    "ipProtocol": "TCP",
                    "receivedBytes": 2048,
                    "sentBytes": 1024,
                    "sessionId": "session-12345",
                    "tls": {
                        "cipher": "AES_128_GCM",
                        "version": "TLSv1.3"
                    }
                },
                "principal": {
                    "application": "web-portal",
                    "asset": {
                        "assetId": "asset-12345",
                        "attribute": {
                            "cloud": {
                                "availabilityZone": "us-east-1a",
                                "environment": "production"
                            },
                            "creationTime": "2024-12-23T10:15:30.000Z",
                            "labels": [
                                {
                                    "key": "owner",
                                    "value": "team-security"
                                },
                                {
                                    "key": "project",
                                    "value": "secops"
                                }
                            ]
                        },
                        "category": "server",
                        "deploymentStatus": "active",
                        "hardware": [
                            {
                                "cpuPlatform": "Intel Xeon",
                                "model": "x86_64",
                                "serialNumber": "SN12345XYZ"
                            }
                        ],
                        "hostname": "sec-server01.example.com",
                        "ip": "192.168.1.10",
                        "lastBootTime": "2024-12-20T08:00:00.000Z",
                        "location": {
                            "name": "Data Center 1"
                        },
                        "natIp": [
                            "1.128.0.0"
                        ],
                        "productObjectId": "poid-67890",
                        "software": [
                            {
                                "version": "v1.2.3"
                            }
                        ]
                    },
                    "assetId": "asset-12345",
                    "group": {
                        "groupDisplayName": "IT Security Group"
                    },
                    "hostname": "sec-client01.example.com",
                    "ip": [
                        "10.0.0.1"
                    ],
                    "ipGeoArtifact": [
                        {
                            "ip": "1.128.0.1",
                            "location": {
                                "countryOrRegion": "US",
                                "regionCoordinates": {
                                    "lat": 51.0950244,
                                    "lon": 4.4477809
                                },
                                "regionLatitude": 40.7128,
                                "regionLongitude": -74.006,
                                "state": "New York"
                            },
                            "network": {
                                "asn": 12345,
                                "carrierName": "ISP-Example",
                                "dnsDomain": "example.com",
                                "organizationName": "Example Corp"
                            }
                        }
                    ],
                    "labels": [
                        {
                            "key": "env",
                            "value": "production"
                        }
                    ],
                    "location": {
                        "city": "New York",
                        "countryOrRegion": "US",
                        "name": "Corporate Office",
                        "regionCoordinates": {
                            "latitude": 51.0950244,
                            "longitude": 4.4477809
                        },
                        "regionLatitude": 40.7128,
                        "regionLongitude": -74.006,
                        "state": "New York"
                    },
                    "namespace": "principal-namespace",
                    "natIp": [
                        "175.16.199.3"
                    ],
                    "network": {
                        "receivedBytes": 5120,
                        "sentBytes": 2048
                    },
                    "platform": "Windows 10",
                    "port": 443,
                    "process": {
                        "commandLine": "C:\\Program Files\\App\\app.exe --arg1",
                        "file": {
                            "fullPath": "C:\\Program Files\\App\\app.exe",
                            "md5": "9e107d9d372bb6826bd81d3542a419d6",
                            "sha1": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                            "sha256": "d7a8fbb307d7809469ca9abcb0082e4ff7bcd8d97ad8b84b76329ac5d89d6bce"
                        },
                        "parentProcess": {
                            "file": {
                                "fullPath": "C:\\Windows\\System32\\cmd.exe"
                            },
                            "pid": 4567
                        },
                        "pid": 7890
                    },
                    "processAncestors": [
                        {
                            "file": {
                                "fullPath": "C:\\Windows\\explorer.exe"
                            },
                            "pid": 1234
                        }
                    ],
                    "resource": {
                        "name": "resource-name",
                        "productObjectId": "res-prod-789",
                        "resourceSubtype": "web-app",
                        "type": "application"
                    },
                    "securityResult": [
                        {
                            "about": {
                                "labels": [
                                    {
                                        "key": "threat",
                                        "value": "malware"
                                    }
                                ]
                            },
                            "detectionFields": [
                                {
                                    "key": "file",
                                    "value": "malicious.exe"
                                }
                            ]
                        }
                    ],
                    "user": {
                        "accountType": "admin",
                        "attribute": {
                            "cloud": {
                                "environment": "corporate"
                            },
                            "creationTime": "2023-01-15T10:00:00.000Z",
                            "labels": [
                                {
                                    "key": "role",
                                    "value": "security-admin"
                                }
                            ],
                            "permissions": [
                                {
                                    "name": "read"
                                },
                                {
                                    "name": "write"
                                }
                            ],
                            "roles": [
                                {
                                    "name": "security-analyst",
                                    "type": "primary"
                                }
                            ]
                        },
                        "emailAddresses": [
                            "admin@example.com"
                        ],
                        "groupIdentifiers": [
                            "group-id-123"
                        ],
                        "productObjectId": "user-prod-123",
                        "userDisplayName": "John Doe",
                        "userid": "jdoe",
                        "windowsSid": "S-1-5-21-123456789-1234567890-1234567890-1001"
                    }
                },
                "securityResult": [
                    {
                        "about": {
                            "labels": [
                                {
                                    "key": "source",
                                    "value": "SIEM"
                                },
                                {
                                    "key": "threatType",
                                    "value": "malware"
                                }
                            ],
                            "namespace": "security-namespace-1",
                            "objectReference": {
                                "id": "malware-incident-12345"
                            },
                            "resource": {
                                "name": "endpoint01"
                            },
                            "user": {
                                "attribute": {
                                    "roles": [
                                        {
                                            "name": "Admin"
                                        },
                                        {
                                            "name": "Security Analyst"
                                        }
                                    ]
                                },
                                "emailAddresses": [
                                    "admin@example.com",
                                    "security@example.com"
                                ]
                            }
                        },
                        "action": [
                            "isolate",
                            "notify"
                        ],
                        "actionDetails": "Endpoint isolated and security team notified",
                        "alertState": "active",
                        "category": [
                            "endpoint",
                            "malware"
                        ],
                        "categoryDetails": [
                            "Critical malware detected on endpoint01"
                        ],
                        "description": "Malware detected on endpoint. Immediate action required.",
                        "detectionFields": [
                            {
                                "key": "hash",
                                "value": "e3b0c44298fc1c149afbf4c8996fb924"
                            },
                            {
                                "key": "filePath",
                                "value": "/var/tmp/malicious.exe"
                            }
                        ],
                        "outcomes": [
                            {
                                "key": "isolationStatus",
                                "value": "success"
                            },
                            {
                                "key": "notificationStatus",
                                "value": "sent"
                            }
                        ],
                        "priority": "high",
                        "priorityDetails": "Critical threat to organization security",
                        "ruleName": "Critical Malware Detection",
                        "severity": "critical",
                        "summary": "Critical malware detected on endpoint01; actions taken: isolation and notification",
                        "urlBackToProduct": "https://securityportal.example.com/incidents/malware-incident-12345"
                    }
                ],
                "src": {
                    "ip": [
                        "175.16.199.0",
                        "175.16.199.1"
                    ],
                    "namespace": "source-namespace-1",
                    "port": 443
                },
                "target": {
                    "administrativeDomain": "example.com",
                    "application": "TargetApp",
                    "asset": {
                        "hostname": "target-endpoint01"
                    },
                    "cloud": {
                        "project": {
                            "name": "Target Cloud Project"
                        }
                    },
                    "file": {
                        "fullPath": "/etc/target.conf",
                        "sha256": "d2d2d2d2e3b0c44298fc1c149afbf4c8996fb924"
                    },
                    "group": {
                        "groupDisplayName": "TargetGroup"
                    },
                    "hostname": "target-server",
                    "ip": [
                        "10.1.1.100",
                        "192.168.50.1"
                    ],
                    "ipGeoArtifact": [
                        {
                            "ip": "10.1.1.100",
                            "location": {
                                "countryOrRegion": "US",
                                "regionCoordinates": {
                                    "lat": 51.0950244,
                                    "lon": 4.4477809
                                },
                                "regionLatitude": 38.5454,
                                "regionLongitude": -120.7394,
                                "state": "California"
                            },
                            "network": {
                                "asn": 15169,
                                "carrierName": "TargetISP",
                                "dnsDomain": "targetisp.com",
                                "organizationName": "TargetISP Corp"
                            }
                        }
                    ],
                    "labels": [
                        {
                            "key": "environment",
                            "value": "production"
                        },
                        {
                            "key": "role",
                            "value": "database-server"
                        }
                    ],
                    "location": {
                        "countryOrRegion": "US",
                        "name": "Target Datacenter",
                        "regionCoordinates": {
                            "latitude": 51.0950244,
                            "longitude": 4.4477809
                        },
                        "regionLatitude": 38.5454,
                        "regionLongitude": -120.7394,
                        "state": "California"
                    },
                    "namespace": "target-namespace",
                    "network": {
                        "sentBytes": 15000
                    },
                    "port": 5432,
                    "process": {
                        "file": {
                            "fullPath": "/usr/bin/target-process"
                        }
                    },
                    "resource": {
                        "attribute": {
                            "cloud": {
                                "availabilityZone": "us-central1-a"
                            },
                            "labels": [
                                {
                                    "key": "team",
                                    "value": "DevOps"
                                },
                                {
                                    "key": "priority",
                                    "value": "high"
                                }
                            ],
                            "permissions": [
                                {
                                    "name": "read"
                                },
                                {
                                    "name": "write"
                                }
                            ]
                        },
                        "name": "TargetResource01",
                        "productObjectId": "resource-obj-12345",
                        "resourceType": "database",
                        "type": "Compute"
                    },
                    "resourceAncestors": [
                        {
                            "attribute": {
                                "labels": [
                                    {
                                        "key": "owner",
                                        "value": "InfrastructureTeam"
                                    },
                                    {
                                        "key": "classification",
                                        "value": "confidential"
                                    }
                                ],
                                "permissions": [
                                    {
                                        "name": "admin"
                                    }
                                ]
                            },
                            "name": "ParentResource01",
                            "productObjectId": "parent-obj-67890",
                            "resourceSubtype": "Cluster",
                            "resourceType": "Kubernetes"
                        }
                    ],
                    "user": {
                        "attribute": {
                            "permissions": [
                                {
                                    "name": "execute"
                                },
                                {
                                    "name": "monitor"
                                }
                            ]
                        },
                        "emailAddresses": [
                            "target.user@example.com"
                        ],
                        "groupIdentifiers": [
                            "target-admins"
                        ],
                        "userDisplayName": "Target User",
                        "userid": "user-1234",
                        "windowsSid": "S-1-5-21-3623811015-3361044348-30300820-1013"
                    }
                }
            }
        }
    },
    "host": {
        "as": {
            "number": [
                12345
            ],
            "organization": {
                "name": [
                    "Example Corp"
                ]
            }
        },
        "geo": {
            "country_name": [
                "US"
            ],
            "location": [
                {
                    "lat": 51.0950244,
                    "lon": 4.4477809
                }
            ],
            "region_name": [
                "New York"
            ]
        },
        "hostname": "sec-client01.example.com",
        "ip": [
            "1.128.0.1",
            "10.0.0.1"
        ]
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "bytes": 3072,
        "transport": "tcp"
    },
    "observer": {
        "product": "SecurityApp",
        "vendor": "ExampleVendor",
        "version": "1.0"
    },
    "process": {
        "command_line": "C:\\Program Files\\App\\app.exe --arg1",
        "parent": {
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "pid": 4567
        },
        "pid": 7890
    },
    "related": {
        "hash": [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "9e107d9d372bb6826bd81d3542a419d6",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "d7a8fbb307d7809469ca9abcb0082e4ff7bcd8d97ad8b84b76329ac5d89d6bce",
            "d2d2d2d2e3b0c44298fc1c149afbf4c8996fb924"
        ],
        "hosts": [
            "proxy01.example.com",
            "sec-server01.example.com",
            "sec-client01.example.com",
            "example.com",
            "target-endpoint01",
            "target-server",
            "targetisp.com"
        ],
        "ip": [
            "192.168.0.1",
            "175.16.199.2",
            "192.168.1.10",
            "1.128.0.0",
            "1.128.0.1",
            "10.0.0.1",
            "175.16.199.3",
            "175.16.199.0",
            "175.16.199.1",
            "10.1.1.100",
            "192.168.50.1"
        ],
        "user": [
            "user123",
            "John Doe",
            "user@example.com",
            "admin@example.com",
            "jdoe",
            "security@example.com",
            "target.user@example.com",
            "user-1234",
            "Target User"
        ]
    },
    "source": {
        "bytes": 1024,
        "ip": [
            "175.16.199.0",
            "175.16.199.1"
        ],
        "port": 443
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_secops-alert"
    ],
    "tls": {
        "cipher": "AES_128_GCM",
        "version": "1.3",
        "version_protocol": "tls"
    },
    "user": {
        "email": [
            "admin@example.com"
        ],
        "group": {
            "id": [
                "group-id-123"
            ]
        },
        "id": "jdoe",
        "name": "John Doe",
        "roles": [
            "security-analyst"
        ]
    },
    "user_agent": {
        "device": {
            "name": "Pixel 6"
        },
        "name": "Chrome Mobile",
        "original": "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Mobile Safari/537.36",
        "os": {
            "full": "Android 12",
            "name": "Android",
            "version": "12"
        },
        "version": "110.0.5481.77"
    },
    "vulnerability": {
        "id": [
            "CVE-2023-12345"
        ],
        "score": {
            "base": [
                9.8
            ]
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
| google_secops.alert.name | The resource name of the event. Format: projects/\{project\}/locations/\{location\}/instances/\{instance\}/events/\{event\} where 'event' is URL-encoded Base64. The unencoded value of 'event' can also be found in udm.metadata.id. | keyword |
| google_secops.alert.udm.about.administrativeDomain | Domain which the device belongs to (for example, the Microsoft Windows domain). | keyword |
| google_secops.alert.udm.about.file.fullPath | The full path identifying the location of the file on the system. | keyword |
| google_secops.alert.udm.about.file.sha256 | The SHA256 hash of the file, as a hex-encoded string. | keyword |
| google_secops.alert.udm.about.group.groupDisplayName | Group display name. | keyword |
| google_secops.alert.udm.about.labels.key | The key. | keyword |
| google_secops.alert.udm.about.labels.value | The value. | keyword |
| google_secops.alert.udm.about.namespace | Namespace which the device belongs to, such as "AD forest". Uses for this field include Microsoft Windows AD forest, the name of subsidiary, or the name of acquisition. | keyword |
| google_secops.alert.udm.about.resource.id |  | keyword |
| google_secops.alert.udm.about.resource.name | The full name of the resource. | keyword |
| google_secops.alert.udm.about.resource.productObjectId | A vendor-specific identifier to uniquely identify the entity (a GUID, OID, or similar). | keyword |
| google_secops.alert.udm.about.resource.resourceType | Resource type. | keyword |
| google_secops.alert.udm.about.resource.type |  | keyword |
| google_secops.alert.udm.about.url | The URL. | keyword |
| google_secops.alert.udm.about.user.attribute.roles.name | System role name for user. | keyword |
| google_secops.alert.udm.about.user.emailAddresses | Email addresses of the user. | keyword |
| google_secops.alert.udm.about.user.groupIdentifiers | Product object identifiers of the group(s) the user belongs to A vendor-specific identifier to uniquely identify the group(s) the user belongs to (a GUID, LDAP OID, or similar). | keyword |
| google_secops.alert.udm.about.user.userDisplayName | The display name of the user (e.g. "John Locke"). | keyword |
| google_secops.alert.udm.about.user.userid | The ID of the user. | keyword |
| google_secops.alert.udm.additional | Any important vendor-specific event data that cannot be adequately represented within the formal sections of the UDM model. | flattened |
| google_secops.alert.udm.extensions.auth.authDetails | The vendor defined details of the authentication. | keyword |
| google_secops.alert.udm.extensions.auth.mechanism | The authentication mechanism. | keyword |
| google_secops.alert.udm.extensions.auth.type | The type of authentication. | keyword |
| google_secops.alert.udm.extensions.vulns.vulnerabilities.about.labels.key | The key. | keyword |
| google_secops.alert.udm.extensions.vulns.vulnerabilities.about.labels.value | The value. | keyword |
| google_secops.alert.udm.extensions.vulns.vulnerabilities.cveId | Common Vulnerabilities and Exposures Id. https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures https://cve.mitre.org/about/faqs.html#what_is_cve_id. | keyword |
| google_secops.alert.udm.extensions.vulns.vulnerabilities.cvssBaseScore | CVSS Base Score in the range of 0.0 to 10.0. Useful for sorting. | double |
| google_secops.alert.udm.extensions.vulns.vulnerabilities.cvssVector | Vector of CVSS properties (e.g. "AV:L/AC:H/Au:N/C:N/I:P/A:C") Can be linked to via: https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator. | keyword |
| google_secops.alert.udm.intermediary.application | The name of an application or service. Some SSO solutions only capture the name of a target application such as "Atlassian" or "Google". | keyword |
| google_secops.alert.udm.intermediary.hostname | Client hostname or domain name field. Hostname also doubles as the domain for remote entities. | keyword |
| google_secops.alert.udm.intermediary.ip | A list of IP addresses associated with a network connection. | ip |
| google_secops.alert.udm.intermediary.location.countryOrRegion | The country or region. | keyword |
| google_secops.alert.udm.intermediary.location.regionCoordinates.latitude | The latitude in degrees. | double |
| google_secops.alert.udm.intermediary.location.regionCoordinates.longitude | The longitude in degrees. | double |
| google_secops.alert.udm.intermediary.namespace | Namespace which the device belongs to, such as "AD forest". Uses for this field include Microsoft Windows AD forest, the name of subsidiary, or the name of acquisition. | keyword |
| google_secops.alert.udm.intermediary.network.receivedBytes | The number of bytes received. | long |
| google_secops.alert.udm.intermediary.network.sentBytes | The number of bytes sent. | long |
| google_secops.alert.udm.intermediary.port | Source or destination network port number when a specific network connection is described within an event. | long |
| google_secops.alert.udm.intermediary.resource.attribute.labels.key | The key. | keyword |
| google_secops.alert.udm.intermediary.resource.attribute.labels.value | The value. | keyword |
| google_secops.alert.udm.metadata.baseLabels.allowScopedAccess |  | boolean |
| google_secops.alert.udm.metadata.baseLabels.logTypes |  | keyword |
| google_secops.alert.udm.metadata.collectedTimestamp | The GMT timestamp when the event was collected by the vendor's local collection infrastructure. | date |
| google_secops.alert.udm.metadata.description | A human-readable unparsable description of the event. | keyword |
| google_secops.alert.udm.metadata.enrichmentLabels.allowScopedAccess |  | boolean |
| google_secops.alert.udm.metadata.enrichmentLabels.logTypes |  | keyword |
| google_secops.alert.udm.metadata.enrichmentState | The enrichment state. | keyword |
| google_secops.alert.udm.metadata.eventTimestamp | The GMT timestamp when the event was generated. | date |
| google_secops.alert.udm.metadata.eventType | The event type. If an event has multiple possible types, this specifies the most specific type. | keyword |
| google_secops.alert.udm.metadata.id | ID of the UDM event. Can be used for raw and normalized event retrieval. | keyword |
| google_secops.alert.udm.metadata.ingestedTimestamp | The GMT timestamp when the event was ingested (received) by Google Security Operations. | date |
| google_secops.alert.udm.metadata.ingestionLabels.key | The key. | keyword |
| google_secops.alert.udm.metadata.ingestionLabels.value | The value. | keyword |
| google_secops.alert.udm.metadata.logType | The string value of log type. | keyword |
| google_secops.alert.udm.metadata.productDeploymentId | The deployment identifier assigned by the vendor for a product deployment. | keyword |
| google_secops.alert.udm.metadata.productEventType | A short, descriptive, human-readable, product-specific event name or type (for example: "Scanned X", "User account created", "process_start"). | keyword |
| google_secops.alert.udm.metadata.productLogId | A vendor-specific event identifier to uniquely identify the event (for example: a GUID). | keyword |
| google_secops.alert.udm.metadata.productName | The name of the product. | keyword |
| google_secops.alert.udm.metadata.productVersion | The version of the product. | keyword |
| google_secops.alert.udm.metadata.urlBackToProduct | A URL that takes the user to the source product console for this event. | keyword |
| google_secops.alert.udm.metadata.vendorName | The name of the product vendor. | keyword |
| google_secops.alert.udm.network.email.from | The 'from' address. | keyword |
| google_secops.alert.udm.network.email.mailId | The mail (or message) ID. | keyword |
| google_secops.alert.udm.network.email.subject | The subject line(s) of the email. | keyword |
| google_secops.alert.udm.network.email.to | A list of 'to' addresses. | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.annotation.key |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.annotation.value |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.browser |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.browserEngineVersion |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.browserVersion |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.device |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.deviceVersion |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.family |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.os |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.osVariant |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.platform |  | keyword |
| google_secops.alert.udm.network.http.parsedUserAgent.subFamily |  | keyword |
| google_secops.alert.udm.network.http.userAgent | The User-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | keyword |
| google_secops.alert.udm.network.ipProtocol | The IP protocol. | keyword |
| google_secops.alert.udm.network.receivedBytes | The number of bytes received. | long |
| google_secops.alert.udm.network.sentBytes | The number of bytes sent. | long |
| google_secops.alert.udm.network.sessionId | The ID of the network session. | keyword |
| google_secops.alert.udm.network.tls.cipher | Cipher used during the connection. | keyword |
| google_secops.alert.udm.network.tls.version | TLS version. | keyword |
| google_secops.alert.udm.principal.application | The name of an application or service. Some SSO solutions only capture the name of a target application such as "Atlassian" or "Google". | keyword |
| google_secops.alert.udm.principal.asset.assetId | The asset ID. | keyword |
| google_secops.alert.udm.principal.asset.attribute.cloud.availabilityZone | The cloud environment availability zone (different from region which is location.name). | keyword |
| google_secops.alert.udm.principal.asset.attribute.cloud.environment | The Cloud environment. | keyword |
| google_secops.alert.udm.principal.asset.attribute.creationTime | Time the resource or entity was created or provisioned. | date |
| google_secops.alert.udm.principal.asset.attribute.labels.key | The key. | keyword |
| google_secops.alert.udm.principal.asset.attribute.labels.value | The value. | keyword |
| google_secops.alert.udm.principal.asset.category | The category of the asset (e.g. "End User Asset", "Workstation", "Server"). | keyword |
| google_secops.alert.udm.principal.asset.deploymentStatus | The deployment status of the asset for device lifecycle purposes. | keyword |
| google_secops.alert.udm.principal.asset.hardware.cpuPlatform | Platform of the hardware CPU (e.g. "Intel Broadwell"). | keyword |
| google_secops.alert.udm.principal.asset.hardware.model | Hardware model. | keyword |
| google_secops.alert.udm.principal.asset.hardware.serialNumber | Hardware serial number. | keyword |
| google_secops.alert.udm.principal.asset.hostname | Asset hostname or domain name field. | keyword |
| google_secops.alert.udm.principal.asset.ip | A list of IP addresses associated with an asset. | ip |
| google_secops.alert.udm.principal.asset.lastBootTime | Time the asset was last boot started. | date |
| google_secops.alert.udm.principal.asset.location.name | Custom location name (e.g. building or site name like "London Office"). For cloud environments, this is the region (e.g. "us-west2"). | keyword |
| google_secops.alert.udm.principal.asset.natIp | List of NAT IP addresses associated with an asset. | ip |
| google_secops.alert.udm.principal.asset.productObjectId | A vendor-specific identifier to uniquely identify the entity (a GUID or similar). | keyword |
| google_secops.alert.udm.principal.asset.software.version | The name of the software. | keyword |
| google_secops.alert.udm.principal.assetId | The asset ID. | keyword |
| google_secops.alert.udm.principal.group.groupDisplayName | Group display name. | keyword |
| google_secops.alert.udm.principal.hostname | Client hostname or domain name field. Hostname also doubles as the domain for remote entities. | keyword |
| google_secops.alert.udm.principal.ip | A list of IP addresses associated with a network connection. | ip |
| google_secops.alert.udm.principal.ipGeoArtifact.ip | IP address of the artifact. | ip |
| google_secops.alert.udm.principal.ipGeoArtifact.location.countryOrRegion | The country or region. | keyword |
| google_secops.alert.udm.principal.ipGeoArtifact.location.regionCoordinates.lat | The latitude in degrees. | double |
| google_secops.alert.udm.principal.ipGeoArtifact.location.regionCoordinates.lon | The longitude in degrees. | double |
| google_secops.alert.udm.principal.ipGeoArtifact.location.regionLatitude |  | double |
| google_secops.alert.udm.principal.ipGeoArtifact.location.regionLongitude |  | double |
| google_secops.alert.udm.principal.ipGeoArtifact.location.state | The state. | keyword |
| google_secops.alert.udm.principal.ipGeoArtifact.network.asn | Autonomous system number. | long |
| google_secops.alert.udm.principal.ipGeoArtifact.network.carrierName | Carrier identification. | keyword |
| google_secops.alert.udm.principal.ipGeoArtifact.network.dnsDomain | DNS domain name. | keyword |
| google_secops.alert.udm.principal.ipGeoArtifact.network.organizationName | Organization name (e.g Google). | keyword |
| google_secops.alert.udm.principal.labels.key | The key. | keyword |
| google_secops.alert.udm.principal.labels.value | The value. | keyword |
| google_secops.alert.udm.principal.location.city | The city. | keyword |
| google_secops.alert.udm.principal.location.countryOrRegion | The country or region. | keyword |
| google_secops.alert.udm.principal.location.name | Custom location name (e.g. building or site name like "London Office"). For cloud environments, this is the region (e.g. "us-west2"). | keyword |
| google_secops.alert.udm.principal.location.regionCoordinates.latitude | The latitude in degrees. | double |
| google_secops.alert.udm.principal.location.regionCoordinates.longitude | The longitude in degrees. | double |
| google_secops.alert.udm.principal.location.regionLatitude |  | double |
| google_secops.alert.udm.principal.location.regionLongitude |  | double |
| google_secops.alert.udm.principal.location.state | The state. | keyword |
| google_secops.alert.udm.principal.namespace | Namespace which the device belongs to, such as "AD forest". Uses for this field include Microsoft Windows AD forest, the name of subsidiary, or the name of acquisition. | keyword |
| google_secops.alert.udm.principal.natIp | A list of NAT translated IP addresses associated with a network connection. | ip |
| google_secops.alert.udm.principal.network.receivedBytes | The number of bytes received. | long |
| google_secops.alert.udm.principal.network.sentBytes | The number of bytes sent. | long |
| google_secops.alert.udm.principal.platform | Platform. | keyword |
| google_secops.alert.udm.principal.port | Source or destination network port number when a specific network connection is described within an event. | long |
| google_secops.alert.udm.principal.process.commandLine | The command line command that created the process. | keyword |
| google_secops.alert.udm.principal.process.file.fullPath | The full path identifying the location of the file on the system. | keyword |
| google_secops.alert.udm.principal.process.file.md5 | The MD5 hash of the file, as a hex-encoded string. | keyword |
| google_secops.alert.udm.principal.process.file.sha1 | The SHA1 hash of the file, as a hex-encoded string. | keyword |
| google_secops.alert.udm.principal.process.file.sha256 | The SHA256 hash of the file, as a hex-encoded string. | keyword |
| google_secops.alert.udm.principal.process.parentProcess.file.fullPath | The full path identifying the location of the file on the system. | keyword |
| google_secops.alert.udm.principal.process.parentProcess.pid | The process ID. | long |
| google_secops.alert.udm.principal.process.pid | The process ID. | long |
| google_secops.alert.udm.principal.processAncestors.file.fullPath | The full path identifying the location of the file on the system. | keyword |
| google_secops.alert.udm.principal.processAncestors.pid | The process ID. | long |
| google_secops.alert.udm.principal.resource.name | The full name of the resource. | keyword |
| google_secops.alert.udm.principal.resource.productObjectId | A vendor-specific identifier to uniquely identify the entity (a GUID, OID, or similar). | keyword |
| google_secops.alert.udm.principal.resource.resourceSubtype | Resource type. | keyword |
| google_secops.alert.udm.principal.resource.type |  | keyword |
| google_secops.alert.udm.principal.securityResult.about.labels.key | The key. | keyword |
| google_secops.alert.udm.principal.securityResult.about.labels.value | The value. | keyword |
| google_secops.alert.udm.principal.securityResult.detectionFields.key | The key. | keyword |
| google_secops.alert.udm.principal.securityResult.detectionFields.value | The value. | keyword |
| google_secops.alert.udm.principal.user.accountType | Type of user account (for example, service, domain, or cloud). This is somewhat aligned to: https://attack.mitre.org/techniques/T1078/. | keyword |
| google_secops.alert.udm.principal.user.attribute.cloud.environment | The Cloud environment. | keyword |
| google_secops.alert.udm.principal.user.attribute.creationTime | Time the resource or entity was created or provisioned. | date |
| google_secops.alert.udm.principal.user.attribute.labels.key | The key. | keyword |
| google_secops.alert.udm.principal.user.attribute.labels.value | The value. | keyword |
| google_secops.alert.udm.principal.user.attribute.permissions.name | Name of the permission (e.g. chronicle.analyst.updateRule). | keyword |
| google_secops.alert.udm.principal.user.attribute.roles.name | System role name for user. | keyword |
| google_secops.alert.udm.principal.user.attribute.roles.type | System role type for well known roles. | keyword |
| google_secops.alert.udm.principal.user.emailAddresses | Email addresses of the user. | keyword |
| google_secops.alert.udm.principal.user.groupIdentifiers | Product object identifiers of the group(s) the user belongs to A vendor-specific identifier to uniquely identify the group(s) the user belongs to (a GUID, LDAP OID, or similar). | keyword |
| google_secops.alert.udm.principal.user.productObjectId | A vendor-specific identifier to uniquely identify the entity (e.g. a GUID, LDAP, OID, or similar). | keyword |
| google_secops.alert.udm.principal.user.userDisplayName | The display name of the user (e.g. "John Locke"). | keyword |
| google_secops.alert.udm.principal.user.userid | The ID of the user. | keyword |
| google_secops.alert.udm.principal.user.windowsSid | The Microsoft Windows SID of the user. | keyword |
| google_secops.alert.udm.securityResult.about.labels.key | The key. | keyword |
| google_secops.alert.udm.securityResult.about.labels.value | The value. | keyword |
| google_secops.alert.udm.securityResult.about.namespace | Namespace which the device belongs to, such as "AD forest". Uses for this field include Microsoft Windows AD forest, the name of subsidiary, or the name of acquisition. | keyword |
| google_secops.alert.udm.securityResult.about.objectReference.id | Finding to which the Analyst updated the feedback. | keyword |
| google_secops.alert.udm.securityResult.about.resource.name | The full name of the resource. | keyword |
| google_secops.alert.udm.securityResult.about.user.attribute.roles.name | System role name for user. | keyword |
| google_secops.alert.udm.securityResult.about.user.emailAddresses | Email addresses of the user. | keyword |
| google_secops.alert.udm.securityResult.action | Actions taken for this event. | keyword |
| google_secops.alert.udm.securityResult.actionDetails | The detail of the action taken as provided by the vendor. | keyword |
| google_secops.alert.udm.securityResult.alertState | The alerting types of this security result. | keyword |
| google_secops.alert.udm.securityResult.category | The security category. | keyword |
| google_secops.alert.udm.securityResult.categoryDetails | For vendor-specific categories. | keyword |
| google_secops.alert.udm.securityResult.description | A human readable description (e.g. "user password was wrong"). | keyword |
| google_secops.alert.udm.securityResult.detectionFields.key | The key. | keyword |
| google_secops.alert.udm.securityResult.detectionFields.value | The value. | keyword |
| google_secops.alert.udm.securityResult.outcomes.key | The key. | keyword |
| google_secops.alert.udm.securityResult.outcomes.value | The value. | keyword |
| google_secops.alert.udm.securityResult.priority | The priority of the result. | keyword |
| google_secops.alert.udm.securityResult.priorityDetails | Vendor-specific information about the security result priority. | keyword |
| google_secops.alert.udm.securityResult.ruleName | Name of the security rule (e.g. "BlockInboundToOracle"). | keyword |
| google_secops.alert.udm.securityResult.severity | The severity of the result. | keyword |
| google_secops.alert.udm.securityResult.summary | A human readable summary (e.g. "failed login occurred"). | keyword |
| google_secops.alert.udm.securityResult.urlBackToProduct | URL that takes the user to the source product console for this event. | keyword |
| google_secops.alert.udm.src.ip | A list of IP addresses associated with a network connection. | ip |
| google_secops.alert.udm.src.namespace | Namespace which the device belongs to, such as "AD forest". Uses for this field include Microsoft Windows AD forest, the name of subsidiary, or the name of acquisition. | keyword |
| google_secops.alert.udm.src.port | Source or destination network port number when a specific network connection is described within an event. | long |
| google_secops.alert.udm.target.administrativeDomain | Domain which the device belongs to (for example, the Microsoft Windows domain). | keyword |
| google_secops.alert.udm.target.application | The name of an application or service. Some SSO solutions only capture the name of a target application such as "Atlassian" or "Google". | keyword |
| google_secops.alert.udm.target.asset.hostname | Asset hostname or domain name field. | keyword |
| google_secops.alert.udm.target.cloud.project.name | The full name of the resource. | keyword |
| google_secops.alert.udm.target.file.fullPath | The full path identifying the location of the file on the system. | keyword |
| google_secops.alert.udm.target.file.sha256 | The SHA256 hash of the file, as a hex-encoded string. | keyword |
| google_secops.alert.udm.target.group.groupDisplayName | Group display name. e.g. "Finance". | keyword |
| google_secops.alert.udm.target.hostname | Client hostname or domain name field. Hostname also doubles as the domain for remote entities. | keyword |
| google_secops.alert.udm.target.ip | A list of IP addresses associated with a network connection. | ip |
| google_secops.alert.udm.target.ipGeoArtifact.ip | IP address of the artifact. | ip |
| google_secops.alert.udm.target.ipGeoArtifact.location.countryOrRegion | The country or region. | keyword |
| google_secops.alert.udm.target.ipGeoArtifact.location.regionCoordinates.lat | The latitude in degrees. | double |
| google_secops.alert.udm.target.ipGeoArtifact.location.regionCoordinates.lon | The longitude in degrees. | double |
| google_secops.alert.udm.target.ipGeoArtifact.location.regionLatitude |  | double |
| google_secops.alert.udm.target.ipGeoArtifact.location.regionLongitude |  | double |
| google_secops.alert.udm.target.ipGeoArtifact.location.state | The state. | keyword |
| google_secops.alert.udm.target.ipGeoArtifact.network.asn | Autonomous system number. | long |
| google_secops.alert.udm.target.ipGeoArtifact.network.carrierName | Carrier identification. | keyword |
| google_secops.alert.udm.target.ipGeoArtifact.network.dnsDomain | DNS domain name. | keyword |
| google_secops.alert.udm.target.ipGeoArtifact.network.organizationName | Organization name (e.g Google). | keyword |
| google_secops.alert.udm.target.labels.key | The key. | keyword |
| google_secops.alert.udm.target.labels.value | The value. | keyword |
| google_secops.alert.udm.target.location.countryOrRegion | The country or region. | keyword |
| google_secops.alert.udm.target.location.name | Custom location name (e.g. building or site name like "London Office"). For cloud environments, this is the region (e.g. "us-west2"). | keyword |
| google_secops.alert.udm.target.location.regionCoordinates.latitude | The latitude in degrees. | double |
| google_secops.alert.udm.target.location.regionCoordinates.longitude | The longitude in degrees. | double |
| google_secops.alert.udm.target.location.regionLatitude |  | double |
| google_secops.alert.udm.target.location.regionLongitude |  | double |
| google_secops.alert.udm.target.location.state | The state. | keyword |
| google_secops.alert.udm.target.namespace | Namespace which the device belongs to, such as "AD forest". Uses for this field include Microsoft Windows AD forest, the name of subsidiary, or the name of acquisition. | keyword |
| google_secops.alert.udm.target.network.sentBytes | The number of bytes sent. | long |
| google_secops.alert.udm.target.port | Source or destination network port number when a specific network connection is described within an event. | long |
| google_secops.alert.udm.target.process.file.fullPath | The full path identifying the location of the file on the system. | keyword |
| google_secops.alert.udm.target.resource.attribute.cloud.availabilityZone | The cloud environment availability zone (different from region which is location.name). | keyword |
| google_secops.alert.udm.target.resource.attribute.labels.key | The key. | keyword |
| google_secops.alert.udm.target.resource.attribute.labels.value | The value. | keyword |
| google_secops.alert.udm.target.resource.attribute.permissions.name | Name of the permission (e.g. chronicle.analyst.updateRule). | keyword |
| google_secops.alert.udm.target.resource.name | The full name of the resource. | keyword |
| google_secops.alert.udm.target.resource.productObjectId | A vendor-specific identifier to uniquely identify the entity (a GUID, OID, or similar). | keyword |
| google_secops.alert.udm.target.resource.resourceType | Resource type. | keyword |
| google_secops.alert.udm.target.resource.type |  | keyword |
| google_secops.alert.udm.target.resourceAncestors.attribute.labels.key | The key. | keyword |
| google_secops.alert.udm.target.resourceAncestors.attribute.labels.value | The value. | keyword |
| google_secops.alert.udm.target.resourceAncestors.attribute.permissions.name | Name of the permission (e.g. chronicle.analyst.updateRule). | keyword |
| google_secops.alert.udm.target.resourceAncestors.name | The full name of the resource. | keyword |
| google_secops.alert.udm.target.resourceAncestors.productObjectId | The full name of the resource. | keyword |
| google_secops.alert.udm.target.resourceAncestors.resourceSubtype | Resource sub-type (e.g. "BigQuery", "Bigtable"). | keyword |
| google_secops.alert.udm.target.resourceAncestors.resourceType | Resource type. | keyword |
| google_secops.alert.udm.target.user.attribute.permissions.name | Name of the permission (e.g. chronicle.analyst.updateRule). | keyword |
| google_secops.alert.udm.target.user.emailAddresses | Email addresses of the user. | keyword |
| google_secops.alert.udm.target.user.groupIdentifiers | Product object identifiers of the group(s) the user belongs to A vendor-specific identifier to uniquely identify the group(s) the user belongs to (a GUID, LDAP OID, or similar). | keyword |
| google_secops.alert.udm.target.user.userDisplayName | The display name of the user (e.g. "John Locke"). | keyword |
| google_secops.alert.udm.target.user.userid | The ID of the user. | keyword |
| google_secops.alert.udm.target.user.windowsSid | The Microsoft Windows SID of the user. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |

