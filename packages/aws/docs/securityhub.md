# Security Hub

The [AWS Security Hub](https://docs.aws.amazon.com/securityhub/) integration collects and parses data from AWS Security Hub REST APIs.

## Compatibility

  1. The minimum compatible version of this module is `Elastic Agent 8.4.0`.
  2. This module is tested against `AWS Security Hub API version 1.0`.

## To collect data from AWS Security Hub APIs, users must have an Access Key and a Secret Key. To create API token follow below steps:

  1. Login to https://console.aws.amazon.com/.
  2. Go to https://console.aws.amazon.com/iam/ to access the IAM console.
  3. On the navigation menu, choose Users.
  4. Choose your IAM user name.
  5. Select Create access key from the Security Credentials tab.
  6. To see the new access key, choose Show.

## Note

  1. For the current integration package, it is recommended to have interval in hours.
  2. For the current integration package, it is compulsory to add Secret Access Key and Access Key ID.

## Logs

### Findings

This is the [`securityhub_findings`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html#API_GetFindings_ResponseElements) data stream.

An example event for `securityhub_findings` looks as following:

```json
{
    "@timestamp": "2017-03-22T13:22:13.933Z",
    "agent": {
        "ephemeral_id": "01f4fdba-8670-479d-b54f-7d39403bb723",
        "id": "eea1c0db-3657-4195-add3-da25a54834e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.0"
    },
    "aws": {
        "securityhub_findings": {
            "action": {
                "port_probe": {
                    "blocked": false,
                    "details": [
                        {
                            "local": {
                                "ip": {
                                    "address_v4": "1.128.0.0"
                                },
                                "port": {
                                    "name": "HTTP",
                                    "number": 80
                                }
                            },
                            "remote_ip": {
                                "city": {
                                    "name": "Example City"
                                },
                                "country": {
                                    "name": "Example Country"
                                },
                                "geolocation": {
                                    "latitude": 0,
                                    "longitude": 0
                                },
                                "organization": {
                                    "asn": "64496",
                                    "asn_organization": "ExampleASO",
                                    "internet_provider": "ExampleOrg",
                                    "internet_service_provider": "ExampleISP"
                                }
                            }
                        }
                    ]
                }
            },
            "aws_account_id": "111111111111",
            "company": {
                "name": "AWS"
            },
            "compliance": {
                "related_requirements": [
                    "Req1",
                    "Req2"
                ],
                "status": "PASSED",
                "status_reasons": [
                    {
                        "description": "CloudWatch alarms do not exist in the account",
                        "reason_code": "CLOUDWATCH_ALARMS_NOT_PRESENT"
                    }
                ]
            },
            "confidence": 42,
            "criticality": 99,
            "description": "The version of openssl found on instance i-abcd1234 is known to contain a vulnerability.",
            "first_observed_at": "2017-03-22T13:22:13.933Z",
            "generator": {
                "id": "acme-vuln-9ab348"
            },
            "last_observed_at": "2017-03-23T13:22:13.933Z",
            "malware": [
                {
                    "name": "Stringler",
                    "path": "/usr/sbin/stringler",
                    "state": "OBSERVED",
                    "type": "COIN_MINER"
                }
            ],
            "network": {
                "open_port_range": {
                    "begin": 443,
                    "end": 443
                }
            },
            "network_path": [
                {
                    "component": {
                        "id": "abc-01a234bc56d8901ee",
                        "type": "AWS::EC2::InternetGateway"
                    },
                    "egress": {
                        "destination": {
                            "address": [
                                "1.128.0.0/24"
                            ],
                            "port_ranges": [
                                {
                                    "begin": 443,
                                    "end": 443
                                }
                            ]
                        },
                        "protocol": "TCP",
                        "source": {
                            "address": [
                                "175.16.199.1/24"
                            ]
                        }
                    },
                    "ingress": {
                        "destination": {
                            "address": [
                                "175.16.199.1/24"
                            ],
                            "port_ranges": [
                                {
                                    "begin": 443,
                                    "end": 443
                                }
                            ]
                        },
                        "protocol": "TCP",
                        "source": {
                            "address": [
                                "175.16.199.1/24"
                            ]
                        }
                    }
                }
            ],
            "note": {
                "text": "Don't forget to check under the mat.",
                "updated_at": "2018-08-31T00:15:09.000Z",
                "updated_by": "jsmith"
            },
            "patch_summary": {
                "failed": {
                    "count": 0
                },
                "id": "pb-123456789098",
                "installed": {
                    "count": 100,
                    "other": {
                        "count": 1023
                    },
                    "pending_reboot": 0,
                    "rejected": {
                        "count": 0
                    }
                },
                "missing": {
                    "count": 100
                },
                "operation": {
                    "end_time": "2018-09-27T23:39:31.000Z",
                    "start_time": "2018-09-27T23:37:31.000Z",
                    "type": "Install"
                },
                "reboot_option": "RebootIfNeeded"
            },
            "product": {
                "arn": "arn:aws:securityhub:us-east-1:111111111111:product/111111111111/default",
                "fields": {
                    "Service_Name": "cloudtrail.amazonaws.com",
                    "aws/inspector/AssessmentTargetName": "My prod env",
                    "aws/inspector/AssessmentTemplateName": "My daily CVE assessment",
                    "aws/inspector/RulesPackageName": "Common Vulnerabilities and Exposures",
                    "generico/secure-pro/Count": "6"
                },
                "name": "Security Hub"
            },
            "provider_fields": {
                "confidence": 42,
                "criticality": 99,
                "related_findings": [
                    {
                        "id": "123e4567-e89b-12d3-a456-426655440000",
                        "product": {
                            "arn": "arn:aws:securityhub:us-west-2::product/aws/guardduty"
                        }
                    }
                ],
                "severity": {
                    "label": "MEDIUM",
                    "original": "MEDIUM"
                },
                "types": [
                    "Software and Configuration Checks/Vulnerabilities/CVE"
                ]
            },
            "record_state": "ACTIVE",
            "region": "us-east-1",
            "related_findings": [
                {
                    "id": "123e4567-e89b-12d3-a456-426655440000",
                    "product": {
                        "arn": "arn:aws:securityhub:us-west-2::product/aws/guardduty"
                    }
                },
                {
                    "id": "AcmeNerfHerder-111111111111-x189dx7824",
                    "product": {
                        "arn": "arn:aws:securityhub:us-west-2::product/aws/guardduty"
                    }
                }
            ],
            "remediation": {
                "recommendation": {
                    "text": "Run sudo yum update and cross your fingers and toes.",
                    "url": "http://myfp.com/recommendations/dangerous_things_and_how_to_fix_them.html"
                }
            },
            "resources": [
                {
                    "Details": {
                        "IamInstanceProfileArn": "arn:aws:iam::123456789012:role/IamInstanceProfileArn",
                        "ImageId": "ami-79fd7eee",
                        "IpV4Addresses": [
                            "175.16.199.1"
                        ],
                        "IpV6Addresses": [
                            "2a02:cf40::"
                        ],
                        "KeyName": "testkey",
                        "LaunchedAt": "2018-09-29T01:25:54Z",
                        "MetadataOptions": {
                            "HttpEndpoint": "enabled",
                            "HttpProtocolIpv6": "enabled",
                            "HttpPutResponseHopLimit": 1,
                            "HttpTokens": "optional",
                            "InstanceMetadataTags": "disabled"
                        },
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": "eni-e5aa89a3"
                            }
                        ],
                        "SubnetId": "PublicSubnet",
                        "Type": "i3.xlarge",
                        "VirtualizationType": "hvm",
                        "VpcId": "TestVPCIpv6"
                    },
                    "Id": "i-cafebabe",
                    "Partition": "aws",
                    "Region": "us-west-2",
                    "Tags": {
                        "billingCode": "Lotus-1-2-3",
                        "needsPatching": "true"
                    },
                    "Type": "AwsEc2Instance"
                }
            ],
            "sample": true,
            "schema": {
                "version": "2018-10-08"
            },
            "severity": {
                "label": "CRITICAL",
                "original": "8.3"
            },
            "source_url": "http://threatintelweekly.org/backdoors/8888",
            "threat_intel_indicators": [
                {
                    "category": "BACKDOOR",
                    "source": "Threat Intel Weekly",
                    "source_url": "http://threatintelweekly.org/backdoors/8888",
                    "value": "175.16.199.1"
                }
            ],
            "title": "EC2.20 Both VPN tunnels for an AWS Site-to-Site VPN connection should be up",
            "types": [
                "Software and Configuration Checks/Vulnerabilities/CVE"
            ],
            "updated_at": "2018-08-31T00:15:09.000Z",
            "user_defined_fields": {
                "comeBackToLater": "Check this again on Monday",
                "reviewedByCio": "true"
            },
            "verification_state": "UNKNOWN",
            "vulnerabilities": [
                {
                    "cvss": [
                        {
                            "base_score": 4.7,
                            "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "version": "V3"
                        },
                        {
                            "base_score": 4.7,
                            "base_vector": "AV:L/AC:M/Au:N/C:C/I:N/A:N",
                            "version": "V2"
                        }
                    ],
                    "related_vulnerabilities": [
                        "CVE-2020-12345"
                    ],
                    "vendor": {
                        "created_at": "2020-01-16T00:01:43.000Z",
                        "severity": "Medium",
                        "updated_at": "2020-01-16T00:01:43.000Z",
                        "url": "https://alas.aws.amazon.com/ALAS-2020-1337.html"
                    },
                    "vulnerable_packages": [
                        {
                            "architecture": "x86_64",
                            "epoch": "1",
                            "name": "openssl",
                            "release": "16.amzn2.0.3",
                            "version": "1.0.2k"
                        }
                    ]
                }
            ],
            "workflow": {
                "state": "NEW",
                "status": "NEW"
            }
        }
    },
    "cloud": {
        "account": {
            "id": "111111111111"
        }
    },
    "data_stream": {
        "dataset": "aws.securityhub_findings",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "domain": "example2.com",
        "ip": [
            "1.128.0.0",
            "2a02:cf40::"
        ],
        "port": 80
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "eea1c0db-3657-4195-add3-da25a54834e7",
        "snapshot": true,
        "version": "8.4.0"
    },
    "event": {
        "action": "port_probe",
        "agent_id_status": "verified",
        "created": "2022-07-27T12:47:41.799Z",
        "dataset": "aws.securityhub_findings",
        "id": "us-west-2/111111111111/98aebb2207407c87f51e89943f12b1ef",
        "ingested": "2022-07-27T12:47:45Z",
        "kind": "event",
        "original": "{\"Action\":{\"ActionType\":\"PORT_PROBE\",\"PortProbeAction\":{\"Blocked\":false,\"PortProbeDetails\":[{\"LocalIpDetails\":{\"IpAddressV4\":\"1.128.0.0\"},\"LocalPortDetails\":{\"Port\":80,\"PortName\":\"HTTP\"},\"RemoteIpDetails\":{\"City\":{\"CityName\":\"Example City\"},\"Country\":{\"CountryName\":\"Example Country\"},\"GeoLocation\":{\"Lat\":0,\"Lon\":0},\"Organization\":{\"Asn\":64496,\"AsnOrg\":\"ExampleASO\",\"Isp\":\"ExampleISP\",\"Org\":\"ExampleOrg\"}}}]}},\"AwsAccountId\":\"111111111111\",\"CompanyName\":\"AWS\",\"Compliance\":{\"RelatedRequirements\":[\"Req1\",\"Req2\"],\"Status\":\"PASSED\",\"StatusReasons\":[{\"Description\":\"CloudWatch alarms do not exist in the account\",\"ReasonCode\":\"CLOUDWATCH_ALARMS_NOT_PRESENT\"}]},\"Confidence\":42,\"CreatedAt\":\"2017-03-22T13:22:13.933Z\",\"Criticality\":99,\"Description\":\"The version of openssl found on instance i-abcd1234 is known to contain a vulnerability.\",\"FindingProviderFields\":{\"Confidence\":42,\"Criticality\":99,\"RelatedFindings\":[{\"Id\":\"123e4567-e89b-12d3-a456-426655440000\",\"ProductArn\":\"arn:aws:securityhub:us-west-2::product/aws/guardduty\"}],\"Severity\":{\"Label\":\"MEDIUM\",\"Original\":\"MEDIUM\"},\"Types\":[\"Software and Configuration Checks/Vulnerabilities/CVE\"]},\"FirstObservedAt\":\"2017-03-22T13:22:13.933Z\",\"GeneratorId\":\"acme-vuln-9ab348\",\"Id\":\"us-west-2/111111111111/98aebb2207407c87f51e89943f12b1ef\",\"LastObservedAt\":\"2017-03-23T13:22:13.933Z\",\"Malware\":[{\"Name\":\"Stringler\",\"Path\":\"/usr/sbin/stringler\",\"State\":\"OBSERVED\",\"Type\":\"COIN_MINER\"}],\"Network\":{\"DestinationDomain\":\"example2.com\",\"DestinationIpV4\":\"1.128.0.0\",\"DestinationIpV6\":\"2a02:cf40::\",\"DestinationPort\":\"80\",\"Direction\":\"IN\",\"OpenPortRange\":{\"Begin\":443,\"End\":443},\"Protocol\":\"TCP\",\"SourceDomain\":\"example1.com\",\"SourceIpV4\":\"1.128.0.0\",\"SourceIpV6\":\"2a02:cf40::\",\"SourceMac\":\"00:0d:83:b1:c0:8e\",\"SourcePort\":\"42\"},\"NetworkPath\":[{\"ComponentId\":\"abc-01a234bc56d8901ee\",\"ComponentType\":\"AWS::EC2::InternetGateway\",\"Egress\":{\"Destination\":{\"Address\":[\"1.128.0.0/24\"],\"PortRanges\":[{\"Begin\":443,\"End\":443}]},\"Protocol\":\"TCP\",\"Source\":{\"Address\":[\"175.16.199.1/24\"]}},\"Ingress\":{\"Destination\":{\"Address\":[\"175.16.199.1/24\"],\"PortRanges\":[{\"Begin\":443,\"End\":443}]},\"Protocol\":\"TCP\",\"Source\":{\"Address\":[\"175.16.199.1/24\"]}}}],\"Note\":{\"Text\":\"Don't forget to check under the mat.\",\"UpdatedAt\":\"2018-08-31T00:15:09Z\",\"UpdatedBy\":\"jsmith\"},\"PatchSummary\":{\"FailedCount\":\"0\",\"Id\":\"pb-123456789098\",\"InstalledCount\":\"100\",\"InstalledOtherCount\":\"1023\",\"InstalledPendingReboot\":\"0\",\"InstalledRejectedCount\":\"0\",\"MissingCount\":\"100\",\"Operation\":\"Install\",\"OperationEndTime\":\"2018-09-27T23:39:31Z\",\"OperationStartTime\":\"2018-09-27T23:37:31Z\",\"RebootOption\":\"RebootIfNeeded\"},\"Process\":{\"LaunchedAt\":\"2018-09-27T22:37:31Z\",\"Name\":\"syslogd\",\"ParentPid\":56789,\"Path\":\"/usr/sbin/syslogd\",\"Pid\":12345,\"TerminatedAt\":\"2018-09-27T23:37:31Z\"},\"ProductArn\":\"arn:aws:securityhub:us-east-1:111111111111:product/111111111111/default\",\"ProductFields\":{\"Service_Name\":\"cloudtrail.amazonaws.com\",\"aws/inspector/AssessmentTargetName\":\"My prod env\",\"aws/inspector/AssessmentTemplateName\":\"My daily CVE assessment\",\"aws/inspector/RulesPackageName\":\"Common Vulnerabilities and Exposures\",\"generico/secure-pro/Count\":\"6\"},\"ProductName\":\"Security Hub\",\"RecordState\":\"ACTIVE\",\"Region\":\"us-east-1\",\"RelatedFindings\":[{\"Id\":\"123e4567-e89b-12d3-a456-426655440000\",\"ProductArn\":\"arn:aws:securityhub:us-west-2::product/aws/guardduty\"},{\"Id\":\"AcmeNerfHerder-111111111111-x189dx7824\",\"ProductArn\":\"arn:aws:securityhub:us-west-2::product/aws/guardduty\"}],\"Remediation\":{\"Recommendation\":{\"Text\":\"Run sudo yum update and cross your fingers and toes.\",\"Url\":\"http://myfp.com/recommendations/dangerous_things_and_how_to_fix_them.html\"}},\"Resources\":[{\"Details\":{\"IamInstanceProfileArn\":\"arn:aws:iam::123456789012:role/IamInstanceProfileArn\",\"ImageId\":\"ami-79fd7eee\",\"IpV4Addresses\":[\"175.16.199.1\"],\"IpV6Addresses\":[\"2a02:cf40::\"],\"KeyName\":\"testkey\",\"LaunchedAt\":\"2018-09-29T01:25:54Z\",\"MetadataOptions\":{\"HttpEndpoint\":\"enabled\",\"HttpProtocolIpv6\":\"enabled\",\"HttpPutResponseHopLimit\":1,\"HttpTokens\":\"optional\",\"InstanceMetadataTags\":\"disabled\"},\"NetworkInterfaces\":[{\"NetworkInterfaceId\":\"eni-e5aa89a3\"}],\"SubnetId\":\"PublicSubnet\",\"Type\":\"i3.xlarge\",\"VirtualizationType\":\"hvm\",\"VpcId\":\"TestVPCIpv6\"},\"Id\":\"i-cafebabe\",\"Partition\":\"aws\",\"Region\":\"us-west-2\",\"Tags\":{\"billingCode\":\"Lotus-1-2-3\",\"needsPatching\":\"true\"},\"Type\":\"AwsEc2Instance\"}],\"Sample\":true,\"SchemaVersion\":\"2018-10-08\",\"Severity\":{\"Label\":\"CRITICAL\",\"Original\":\"8.3\"},\"SourceUrl\":\"http://threatintelweekly.org/backdoors/8888\",\"ThreatIntelIndicators\":[{\"Category\":\"BACKDOOR\",\"LastObservedAt\":\"2018-09-27T23:37:31Z\",\"Source\":\"Threat Intel Weekly\",\"SourceUrl\":\"http://threatintelweekly.org/backdoors/8888\",\"Type\":\"IPV4_ADDRESS\",\"Value\":\"175.16.199.1\"}],\"Threats\":[{\"FilePaths\":[{\"FileName\":\"b.txt\",\"FilePath\":\"/tmp/b.txt\",\"Hash\":\"sha256\",\"ResourceId\":\"arn:aws:ec2:us-west-2:123456789012:volume/vol-032f3bdd89aee112f\"}],\"ItemCount\":3,\"Name\":\"Iot.linux.mirai.vwisi\",\"Severity\":\"HIGH\"}],\"Title\":\"EC2.20 Both VPN tunnels for an AWS Site-to-Site VPN connection should be up\",\"Types\":[\"Software and Configuration Checks/Vulnerabilities/CVE\"],\"UpdatedAt\":\"2018-08-31T00:15:09Z\",\"UserDefinedFields\":{\"comeBackToLater\":\"Check this again on Monday\",\"reviewedByCio\":\"true\"},\"VerificationState\":\"UNKNOWN\",\"Vulnerabilities\":[{\"Cvss\":[{\"BaseScore\":4.7,\"BaseVector\":\"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N\",\"Version\":\"V3\"},{\"BaseScore\":4.7,\"BaseVector\":\"AV:L/AC:M/Au:N/C:C/I:N/A:N\",\"Version\":\"V2\"}],\"Id\":\"CVE-2020-12345\",\"ReferenceUrls\":[\"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12418\",\"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17563\"],\"RelatedVulnerabilities\":[\"CVE-2020-12345\"],\"Vendor\":{\"Name\":\"Alas\",\"Url\":\"https://alas.aws.amazon.com/ALAS-2020-1337.html\",\"VendorCreatedAt\":\"2020-01-16T00:01:43Z\",\"VendorSeverity\":\"Medium\",\"VendorUpdatedAt\":\"2020-01-16T00:01:43Z\"},\"VulnerablePackages\":[{\"Architecture\":\"x86_64\",\"Epoch\":\"1\",\"Name\":\"openssl\",\"Release\":\"16.amzn2.0.3\",\"Version\":\"1.0.2k\"}]}],\"Workflow\":{\"Status\":\"NEW\"},\"WorkflowState\":\"NEW\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "direction": "IN",
        "protocol": "tcp"
    },
    "organization": {
        "name": "AWS"
    },
    "process": {
        "end": "2018-09-27T23:37:31.000Z",
        "executable": "/usr/sbin/syslogd",
        "name": "syslogd",
        "parent": {
            "pid": 56789
        },
        "pid": 12345,
        "start": "2018-09-27T22:37:31.000Z"
    },
    "related": {
        "ip": [
            "1.128.0.0",
            "2a02:cf40::"
        ]
    },
    "source": {
        "domain": "example1.com",
        "ip": [
            "1.128.0.0",
            "2a02:cf40::"
        ],
        "mac": "00-0D-83-B1-C0-8E",
        "port": 42
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "aws_securityhub_findings"
    ],
    "threat": {
        "indicator": {
            "last_seen": "2018-09-27T23:37:31.000Z",
            "type": "IPV4_ADDRESS"
        }
    },
    "url": {
        "domain": "threatintelweekly.org",
        "full": "http://threatintelweekly.org/backdoors/8888",
        "original": "http://threatintelweekly.org/backdoors/8888",
        "path": "/backdoors/8888",
        "scheme": "http"
    },
    "vulnerability": {
        "id": "CVE-2020-12345",
        "reference": [
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12418",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17563"
        ],
        "scanner": {
            "vendor": "Alas"
        },
        "score": {
            "base": 4.7,
            "version": "V2"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.securityhub_findings.action.aws_api_call.affected_resources | Identifies the resources that were affected by the API call. | flattened |
| aws.securityhub_findings.action.aws_api_call.api | The name of the API method that was issued. | keyword |
| aws.securityhub_findings.action.aws_api_call.caller.type | Indicates whether the API call originated from a remote IP address(remoteip) or from a DNS domain(domain). | keyword |
| aws.securityhub_findings.action.aws_api_call.domain_details.domain | The name of the DNS domain that issued the API call. | keyword |
| aws.securityhub_findings.action.aws_api_call.first_seen | An ISO8601-formatted timestamp that indicates when the API call was first observed. | date |
| aws.securityhub_findings.action.aws_api_call.last_seen | An ISO8601-formatted timestamp that indicates when the API call was most recently observed. | date |
| aws.securityhub_findings.action.aws_api_call.remote_ip.city.name | The name of the city. | keyword |
| aws.securityhub_findings.action.aws_api_call.remote_ip.country.code | The 2-letter ISO 3166 country code for the country. | keyword |
| aws.securityhub_findings.action.aws_api_call.remote_ip.country.name | The name of the country. | keyword |
| aws.securityhub_findings.action.aws_api_call.remote_ip.geolocation.latitude | The longitude of the location. | double |
| aws.securityhub_findings.action.aws_api_call.remote_ip.geolocation.longitude | The latitude of the location. | double |
| aws.securityhub_findings.action.aws_api_call.remote_ip.ip.address_v4 | The IP address. | ip |
| aws.securityhub_findings.action.aws_api_call.remote_ip.organization.asn | The Autonomous System Number(ASN) of the internet provider. | keyword |
| aws.securityhub_findings.action.aws_api_call.remote_ip.organization.asn_organization | The name of the organization that registered the ASN. | keyword |
| aws.securityhub_findings.action.aws_api_call.remote_ip.organization.internet_provider | The ISP information for the internet provider. | keyword |
| aws.securityhub_findings.action.aws_api_call.remote_ip.organization.internet_service_provider | The name of the internet provider. | keyword |
| aws.securityhub_findings.action.aws_api_call.service.name | The name of the Amazon Web Services service that the API method belongs to. | keyword |
| aws.securityhub_findings.action.dns_request.blocked | Indicates whether the DNS request was blocked. | boolean |
| aws.securityhub_findings.action.dns_request.domain | The DNS domain that is associated with the DNS request. | keyword |
| aws.securityhub_findings.action.dns_request.protocol | The protocol that was used for the DNS request. | keyword |
| aws.securityhub_findings.action.network_connection.blocked | Indicates whether the network connection attempt was blocked. | boolean |
| aws.securityhub_findings.action.network_connection.direction | The direction of the network connection request(IN or OUT). | keyword |
| aws.securityhub_findings.action.network_connection.local.port.name | The port name of the local connection. | keyword |
| aws.securityhub_findings.action.network_connection.local.port.number | The number of the port. | long |
| aws.securityhub_findings.action.network_connection.protocol | The protocol used to make the network connection request. | keyword |
| aws.securityhub_findings.action.network_connection.remote.port.name | The port name of the remote connection. | keyword |
| aws.securityhub_findings.action.network_connection.remote.port.number | The number of the port. | long |
| aws.securityhub_findings.action.network_connection.remote_ip.city.name | The name of the city. | keyword |
| aws.securityhub_findings.action.network_connection.remote_ip.country.code | The 2-letter ISO 3166 country code for the country. | keyword |
| aws.securityhub_findings.action.network_connection.remote_ip.country.name | The name of the country. | keyword |
| aws.securityhub_findings.action.network_connection.remote_ip.geolocation.latitude | The longitude of the location. | double |
| aws.securityhub_findings.action.network_connection.remote_ip.geolocation.longitude | The latitude of the location. | double |
| aws.securityhub_findings.action.network_connection.remote_ip.ip.address_v4 | The IP address. | ip |
| aws.securityhub_findings.action.network_connection.remote_ip.organization.asn | The Autonomous System Number(ASN) of the internet provider. | keyword |
| aws.securityhub_findings.action.network_connection.remote_ip.organization.asn_organization | The name of the organization that registered the ASN. | keyword |
| aws.securityhub_findings.action.network_connection.remote_ip.organization.internet_provider | The ISP information for the internet provider. | keyword |
| aws.securityhub_findings.action.network_connection.remote_ip.organization.internet_service_provider | The name of the internet provider. | keyword |
| aws.securityhub_findings.action.port_probe.blocked | Indicates whether the port probe was blocked. | boolean |
| aws.securityhub_findings.action.port_probe.details.local.ip.address_v4 | The IP address. | ip |
| aws.securityhub_findings.action.port_probe.details.local.port.name | The port name of the local connection. | keyword |
| aws.securityhub_findings.action.port_probe.details.local.port.number | The number of the port. | long |
| aws.securityhub_findings.action.port_probe.details.remote_ip.city.name | The name of the city. | keyword |
| aws.securityhub_findings.action.port_probe.details.remote_ip.country.code | The 2-letter ISO 3166 country code for the country. | keyword |
| aws.securityhub_findings.action.port_probe.details.remote_ip.country.name | The name of the country. | keyword |
| aws.securityhub_findings.action.port_probe.details.remote_ip.geolocation.latitude | The longitude of the location. | double |
| aws.securityhub_findings.action.port_probe.details.remote_ip.geolocation.longitude | The latitude of the location. | double |
| aws.securityhub_findings.action.port_probe.details.remote_ip.ip.address_v4 | The IP address. | ip |
| aws.securityhub_findings.action.port_probe.details.remote_ip.organization.asn | The Autonomous System Number(ASN) of the internet provider. | keyword |
| aws.securityhub_findings.action.port_probe.details.remote_ip.organization.asn_organization | The name of the organization that registered the ASN. | keyword |
| aws.securityhub_findings.action.port_probe.details.remote_ip.organization.internet_provider | The ISP information for the internet provider. | keyword |
| aws.securityhub_findings.action.port_probe.details.remote_ip.organization.internet_service_provider | The name of the internet provider. | keyword |
| aws.securityhub_findings.action.type | The type of action that was detected. | keyword |
| aws.securityhub_findings.aws_account_id | The Amazon Web Services account ID that a finding is generated in. | keyword |
| aws.securityhub_findings.company.name | The name of the company for the product that generated the finding. | keyword |
| aws.securityhub_findings.compliance.related_requirements | For a control, the industry or regulatory framework requirements that are related to the control. | keyword |
| aws.securityhub_findings.compliance.status | The result of a standards check. | keyword |
| aws.securityhub_findings.compliance.status_reasons.description | The corresponding description for the status reason code. | keyword |
| aws.securityhub_findings.compliance.status_reasons.reason_code | A code that represents a reason for the control status. | keyword |
| aws.securityhub_findings.confidence | A finding's confidence. Confidence is defined as the likelihood that a finding accurately identifies the behavior or issue that it was intended to identify. | long |
| aws.securityhub_findings.created_at | Indicates when the security-findings provider created the potential security issue that a finding captured. | date |
| aws.securityhub_findings.criticality | The level of importance assigned to the resources associated with the finding. | long |
| aws.securityhub_findings.description | A finding's description. | keyword |
| aws.securityhub_findings.first_observed_at | Indicates when the security-findings provider first observed the potential security issue that a finding captured. | date |
| aws.securityhub_findings.generator.id | The identifier for the solution-specific component(a discrete unit of logic) that generated a finding. In various security-findings providers' solutions, this generator can be called a rule, a check, a detector, a plugin, etc. | keyword |
| aws.securityhub_findings.id | The security findings provider-specific identifier for a finding. | keyword |
| aws.securityhub_findings.last_observed_at | Indicates when the security-findings provider most recently observed the potential security issue that a finding captured. | date |
| aws.securityhub_findings.malware.name | The name of the malware that was observed. | keyword |
| aws.securityhub_findings.malware.path | The file system path of the malware that was observed. | keyword |
| aws.securityhub_findings.malware.state | The state of the malware that was observed. | keyword |
| aws.securityhub_findings.malware.type | The type of the malware that was observed. | keyword |
| aws.securityhub_findings.network.destination.domain | The destination domain of network-related information about a finding. | keyword |
| aws.securityhub_findings.network.destination.ip.v4 | The destination IPv4 address of network-related information about a finding. | ip |
| aws.securityhub_findings.network.destination.ip.v6 | The destination IPv6 address of network-related information about a finding. | ip |
| aws.securityhub_findings.network.destination.port | The destination port of network-related information about a finding. | long |
| aws.securityhub_findings.network.direction | The direction of network traffic associated with a finding. | keyword |
| aws.securityhub_findings.network.open_port_range.begin | The first port in the port range. | long |
| aws.securityhub_findings.network.open_port_range.end | The last port in the port range. | long |
| aws.securityhub_findings.network.protocol | The protocol of network-related information about a finding. | keyword |
| aws.securityhub_findings.network.source.domain | The source domain of network-related information about a finding. | keyword |
| aws.securityhub_findings.network.source.ip.v4 | The source IPv4 address of network-related information about a finding. | ip |
| aws.securityhub_findings.network.source.ip.v6 | The source IPv6 address of network-related information about a finding. | ip |
| aws.securityhub_findings.network.source.mac | The source media access control(MAC) address of network-related information about a finding. | keyword |
| aws.securityhub_findings.network.source.port | The source port of network-related information about a finding. | long |
| aws.securityhub_findings.network_path.component.id | The identifier of a component in the network path. | keyword |
| aws.securityhub_findings.network_path.component.type | The type of component. | keyword |
| aws.securityhub_findings.network_path.egress.destination.address | The IP addresses of the destination. | keyword |
| aws.securityhub_findings.network_path.egress.destination.port_ranges.begin | The first port in the port range. | long |
| aws.securityhub_findings.network_path.egress.destination.port_ranges.end | The last port in the port range. | long |
| aws.securityhub_findings.network_path.egress.protocol | The protocol used for the component. | keyword |
| aws.securityhub_findings.network_path.egress.source.address | The IP addresses of the destination. | keyword |
| aws.securityhub_findings.network_path.egress.source.port_ranges.begin | The first port in the port range. | long |
| aws.securityhub_findings.network_path.egress.source.port_ranges.end | The last port in the port range. | long |
| aws.securityhub_findings.network_path.ingress.destination.address | The IP addresses of the destination. | keyword |
| aws.securityhub_findings.network_path.ingress.destination.port_ranges.begin | The first port in the port range. | long |
| aws.securityhub_findings.network_path.ingress.destination.port_ranges.end | The last port in the port range. | long |
| aws.securityhub_findings.network_path.ingress.protocol | The protocol used for the component. | keyword |
| aws.securityhub_findings.network_path.ingress.source.address | The IP addresses of the destination. | keyword |
| aws.securityhub_findings.network_path.ingress.source.port_ranges.begin | The first port in the port range. | long |
| aws.securityhub_findings.network_path.ingress.source.port_ranges.end | The last port in the port range. | long |
| aws.securityhub_findings.note.text | The text of a note. | keyword |
| aws.securityhub_findings.note.updated_at | The timestamp of when the note was updated. | date |
| aws.securityhub_findings.note.updated_by | The principal that created a note. | keyword |
| aws.securityhub_findings.patch_summary.failed.count | The number of patches from the compliance standard that failed to install. | long |
| aws.securityhub_findings.patch_summary.id | The identifier of the compliance standard that was used to determine the patch compliance status. | keyword |
| aws.securityhub_findings.patch_summary.installed.count | The number of patches from the compliance standard that were installed successfully. | long |
| aws.securityhub_findings.patch_summary.installed.other.count | The number of installed patches that are not part of the compliance standard. | long |
| aws.securityhub_findings.patch_summary.installed.pending_reboot | The number of patches that were applied, but that require the instance to be rebooted in order to be marked as installed. | long |
| aws.securityhub_findings.patch_summary.installed.rejected.count | The number of patches that are installed but are also on a list of patches that the customer rejected. | long |
| aws.securityhub_findings.patch_summary.missing.count | The number of patches that are part of the compliance standard but are not installed. The count includes patches that failed to install. | long |
| aws.securityhub_findings.patch_summary.operation.end_time | Indicates when the operation completed. | date |
| aws.securityhub_findings.patch_summary.operation.start_time | Indicates when the operation started. | date |
| aws.securityhub_findings.patch_summary.operation.type | The type of patch operation performed. For Patch Manager, the values are SCAN and INSTALL. | keyword |
| aws.securityhub_findings.patch_summary.reboot_option | The reboot option specified for the instance. | keyword |
| aws.securityhub_findings.process.launched_at | Indicates when the process was launched. | date |
| aws.securityhub_findings.process.name | The name of the process. | keyword |
| aws.securityhub_findings.process.parent.pid | The parent process ID. | long |
| aws.securityhub_findings.process.path | The path to the process executable. | keyword |
| aws.securityhub_findings.process.pid | The process ID. | long |
| aws.securityhub_findings.process.terminated_at | Indicates when the process was terminated. | date |
| aws.securityhub_findings.product.arn | The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration. | keyword |
| aws.securityhub_findings.product.fields | A data type where security-findings providers can include additional solution-specific details that aren't part of the defined AwsSecurityFinding format. | flattened |
| aws.securityhub_findings.product.name | The name of the product that generated the finding. | keyword |
| aws.securityhub_findings.provider_fields.confidence | A finding's confidence. Confidence is defined as the likelihood that a finding accurately identifies the behavior or issue that it was intended to identify. | long |
| aws.securityhub_findings.provider_fields.criticality | The level of importance assigned to the resources associated with the finding. | long |
| aws.securityhub_findings.provider_fields.related_findings.id | The product-generated identifier for a related finding. | keyword |
| aws.securityhub_findings.provider_fields.related_findings.product.arn | The ARN of the product that generated a related finding. | keyword |
| aws.securityhub_findings.provider_fields.severity.label | The severity label assigned to the finding by the finding provider. | keyword |
| aws.securityhub_findings.provider_fields.severity.normalized | The normalized severity of a finding provider. | keyword |
| aws.securityhub_findings.provider_fields.severity.original | The finding provider's original value for the severity. | keyword |
| aws.securityhub_findings.provider_fields.severity.product | The finding provider's product for the severity. | keyword |
| aws.securityhub_findings.provider_fields.types | One or more finding types in the format of namespace/category/classifier that classify a finding. | keyword |
| aws.securityhub_findings.record_state | The record state of a finding. | keyword |
| aws.securityhub_findings.region | The Region from which the finding was generated. | keyword |
| aws.securityhub_findings.related_findings.id | The product-generated identifier for a related finding. | keyword |
| aws.securityhub_findings.related_findings.product.arn | The ARN of the product that generated a related finding. | keyword |
| aws.securityhub_findings.remediation.recommendation.text | Describes the recommended steps to take to remediate an issue identified in a finding. | text |
| aws.securityhub_findings.remediation.recommendation.url | A URL to a page or site that contains information about how to remediate a finding. | keyword |
| aws.securityhub_findings.resources | A set of resource data types that describe the resources that the finding refers to. | flattened |
| aws.securityhub_findings.sample | Indicates whether the finding is a sample finding. | boolean |
| aws.securityhub_findings.schema.version | The schema version that a finding is formatted for. | keyword |
| aws.securityhub_findings.severity.label | The severity value of the finding. | keyword |
| aws.securityhub_findings.severity.normalized | The normalized severity of a finding. | keyword |
| aws.securityhub_findings.severity.original | The native severity from the finding product that generated the finding. | keyword |
| aws.securityhub_findings.severity.product | The native severity as defined by the Amazon Web Services service or integrated partner product that generated the finding. | keyword |
| aws.securityhub_findings.source_url | A URL that links to a page about the current finding in the security-findings provider's solution. | keyword |
| aws.securityhub_findings.threat_intel_indicators.category | The category of a threat intelligence indicator. | keyword |
| aws.securityhub_findings.threat_intel_indicators.last_observed_at | Indicates when the most recent instance of a threat intelligence indicator was observed. | date |
| aws.securityhub_findings.threat_intel_indicators.source | The source of the threat intelligence indicator. | keyword |
| aws.securityhub_findings.threat_intel_indicators.source_url | The URL to the page or site where you can get more information about the threat intelligence indicator. | keyword |
| aws.securityhub_findings.threat_intel_indicators.type | The type of threat intelligence indicator. | keyword |
| aws.securityhub_findings.threat_intel_indicators.value | The value of a threat intelligence indicator. | keyword |
| aws.securityhub_findings.title | A finding's title. | text |
| aws.securityhub_findings.types | One or more finding types in the format of namespace/category/classifier that classify a finding. | keyword |
| aws.securityhub_findings.updated_at | Indicates when the security-findings provider last updated the finding record. | date |
| aws.securityhub_findings.user_defined_fields | A list of name/value string pairs associated with the finding. These are custom, user-defined fields added to a finding. | flattened |
| aws.securityhub_findings.verification_state | Indicates the veracity of a finding. | keyword |
| aws.securityhub_findings.vulnerabilities.cvss.adjustments.metric | The metric to adjust. | keyword |
| aws.securityhub_findings.vulnerabilities.cvss.adjustments.reason | The reason for the adjustment. | keyword |
| aws.securityhub_findings.vulnerabilities.cvss.base_score | The base CVSS score. | double |
| aws.securityhub_findings.vulnerabilities.cvss.base_vector | The base scoring vector for the CVSS score. | keyword |
| aws.securityhub_findings.vulnerabilities.cvss.source | The origin of the original CVSS score and vector. | keyword |
| aws.securityhub_findings.vulnerabilities.cvss.version | The version of CVSS for the CVSS score. | keyword |
| aws.securityhub_findings.vulnerabilities.id | The identifier of the vulnerability. | keyword |
| aws.securityhub_findings.vulnerabilities.reference_urls | A list of URLs that provide additional information about the vulnerability. | keyword |
| aws.securityhub_findings.vulnerabilities.related_vulnerabilities | List of vulnerabilities that are related to this vulnerability. | keyword |
| aws.securityhub_findings.vulnerabilities.vendor.created_at | Indicates when the vulnerability advisory was created. | date |
| aws.securityhub_findings.vulnerabilities.vendor.name | The name of the vendor. | keyword |
| aws.securityhub_findings.vulnerabilities.vendor.severity | The severity that the vendor assigned to the vulnerability. | keyword |
| aws.securityhub_findings.vulnerabilities.vendor.updated_at | Indicates when the vulnerability advisory was last updated. | date |
| aws.securityhub_findings.vulnerabilities.vendor.url | The URL of the vulnerability advisory. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.architecture | The architecture used for the software package. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.epoch | The epoch of the software package. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.file_path | The file system path to the package manager inventory file. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.name | The name of the software package. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.package_manager | The source of the package. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.release | The release of the software package. | keyword |
| aws.securityhub_findings.vulnerabilities.vulnerable_packages.version | The version of the software package. | keyword |
| aws.securityhub_findings.workflow.state | The workflow state of a finding. | keyword |
| aws.securityhub_findings.workflow.status | The status of the investigation into the finding. | keyword |
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| process.end | The time the process ended. | date |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.ip | All of the IPs seen on your event. | ip |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.user_info |  | keyword |
| url.username | Username of the request. | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.score.version | The National Vulnerability Database (NVD) provides qualitative severity rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges in addition to the severity ratings for CVSS v3.0 as they are defined in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |


### Insights

This is the [`securityhub_insights`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetInsights.html#API_GetInsights_ResponseElements) data stream.

An example event for `securityhub_insights` looks as following:

```json
{
    "@timestamp": "2022-07-27T12:48:31.384Z",
    "agent": {
        "ephemeral_id": "9a16ab92-dc6a-4607-a737-3e7e7884804e",
        "id": "eea1c0db-3657-4195-add3-da25a54834e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.0"
    },
    "aws": {
        "securityhub_insights": {
            "filters": {
                "aws_account_id": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "company": {
                    "name": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "compliance": {
                    "status": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "confidence": [
                    {
                        "Eq": 20,
                        "Gte": 20,
                        "Lte": 20
                    }
                ],
                "created_at": [
                    {
                        "date_range": {
                            "unit": "string",
                            "value": 20
                        },
                        "end": "2020-07-10T15:00:00.000Z",
                        "start": "2020-07-10T15:00:00.000Z"
                    }
                ],
                "criticality": [
                    {
                        "Eq": 20,
                        "Gte": 20,
                        "Lte": 20
                    }
                ],
                "description": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "finding_provider_fields": {
                    "confidence": [
                        {
                            "Eq": 20,
                            "Gte": 20,
                            "Lte": 20
                        }
                    ],
                    "criticality": [
                        {
                            "Eq": 20,
                            "Gte": 20,
                            "Lte": 20
                        }
                    ],
                    "related_findings": {
                        "id": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "product": {
                            "arn": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        }
                    },
                    "severity": {
                        "label": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "original": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ]
                    },
                    "types": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "first_observed_at": [
                    {
                        "date_range": {
                            "unit": "string",
                            "value": 20
                        },
                        "end": "2020-07-10T15:00:00.000Z",
                        "start": "2020-07-10T15:00:00.000Z"
                    }
                ],
                "generator": {
                    "id": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "id": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "keyword": [
                    {
                        "Value": "string"
                    }
                ],
                "last_observed_at": [
                    {
                        "date_range": {
                            "unit": "string",
                            "value": 20
                        },
                        "end": "2020-07-10T15:00:00.000Z",
                        "start": "2020-07-10T15:00:00.000Z"
                    }
                ],
                "malware": {
                    "name": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "path": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "state": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "type": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "network": {
                    "destination": {
                        "domain": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "ip": {
                            "v4": [
                                {
                                    "Cidr": "string"
                                }
                            ],
                            "v6": [
                                {
                                    "Cidr": "string"
                                }
                            ]
                        },
                        "port": [
                            {
                                "Eq": 20,
                                "Gte": 20,
                                "Lte": 20
                            }
                        ]
                    },
                    "direction": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "protocol": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "source": {
                        "domain": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "ip": {
                            "v4": [
                                {
                                    "Cidr": "string"
                                }
                            ],
                            "v6": [
                                {
                                    "Cidr": "string"
                                }
                            ]
                        },
                        "mac": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "port": [
                            {
                                "Eq": 20,
                                "Gte": 20,
                                "Lte": 20
                            }
                        ]
                    }
                },
                "note": {
                    "text": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "updated_at": [
                        {
                            "date_range": {
                                "unit": "string",
                                "value": 20
                            },
                            "end": "2020-07-10T15:00:00.000Z",
                            "start": "2020-07-10T15:00:00.000Z"
                        }
                    ],
                    "updated_by": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "process": {
                    "launched_at": [
                        {
                            "date_range": {
                                "unit": "string",
                                "value": 20
                            },
                            "end": "2020-07-10T15:00:00.000Z",
                            "start": "2020-07-10T15:00:00.000Z"
                        }
                    ],
                    "name": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "parent": {
                        "pid": [
                            {
                                "Eq": 20,
                                "Gte": 20,
                                "Lte": 20
                            }
                        ]
                    },
                    "path": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "pid": [
                        {
                            "Eq": 20,
                            "Gte": 20,
                            "Lte": 20
                        }
                    ],
                    "terminated_at": [
                        {
                            "date_range": {
                                "unit": "string",
                                "value": 20
                            },
                            "end": "2020-07-10T15:00:00.000Z",
                            "start": "2020-07-10T15:00:00.000Z"
                        }
                    ]
                },
                "product": {
                    "arn": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "fields": [
                        {
                            "Comparison": "string",
                            "Key": "string",
                            "Value": "string"
                        }
                    ],
                    "name": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "recommendation_text": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "record_state": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "region": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "related_findings": {
                    "id": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "product": {
                        "arn": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ]
                    }
                },
                "resource": {
                    "aws_ec2_instance": {
                        "iam_instance_profile": {
                            "arn": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        },
                        "image": {
                            "id": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        },
                        "ip": {
                            "v4_addresses": [
                                {
                                    "Cidr": "string"
                                }
                            ],
                            "v6_addresses": [
                                {
                                    "Cidr": "string"
                                }
                            ]
                        },
                        "key": {
                            "name": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        },
                        "launched_at": [
                            {
                                "date_range": {
                                    "unit": "string",
                                    "value": 20
                                },
                                "end": "2020-07-10T15:00:00.000Z",
                                "start": "2020-07-10T15:00:00.000Z"
                            }
                        ],
                        "subnet": {
                            "id": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        },
                        "type": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "vpc": {
                            "id": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        }
                    },
                    "aws_iam_access_key": {
                        "created_at": [
                            {
                                "date_range": {
                                    "unit": "string",
                                    "value": 20
                                },
                                "end": "2020-07-10T15:00:00.000Z",
                                "start": "2020-07-10T15:00:00.000Z"
                            }
                        ],
                        "principal": {
                            "name": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        },
                        "status": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ],
                        "user": {
                            "name": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        }
                    },
                    "aws_iam_user": {
                        "user": {
                            "name": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        }
                    },
                    "aws_s3_bucket": {
                        "owner": {
                            "id": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ],
                            "name": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        }
                    },
                    "container": {
                        "image": {
                            "id": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ],
                            "name": [
                                {
                                    "Comparison": "string",
                                    "Value": "string"
                                }
                            ]
                        },
                        "launched_at": [
                            {
                                "date_range": {
                                    "unit": "string",
                                    "value": 20
                                },
                                "end": "2020-07-10T15:00:00.000Z",
                                "start": "2020-07-10T15:00:00.000Z"
                            }
                        ],
                        "name": [
                            {
                                "Comparison": "string",
                                "Value": "string"
                            }
                        ]
                    },
                    "details_other": [
                        {
                            "Comparison": "string",
                            "Key": "string",
                            "Value": "string"
                        }
                    ],
                    "id": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "partition": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "region": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "tags": [
                        {
                            "Comparison": "string",
                            "Key": "string",
                            "Value": "string"
                        }
                    ],
                    "type": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "sample": [
                    {
                        "Value": true
                    }
                ],
                "severity": {
                    "label": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "normalized": [
                        {
                            "Eq": 20,
                            "Gte": 20,
                            "Lte": 20
                        }
                    ],
                    "product": [
                        {
                            "Eq": 20,
                            "Gte": 20,
                            "Lte": 20
                        }
                    ]
                },
                "source_url": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "threat_intel_indicator": {
                    "category": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "last_observed_at": [
                        {
                            "date_range": {
                                "unit": "string",
                                "value": 20
                            },
                            "end": "2020-07-10T15:00:00.000Z",
                            "start": "2020-07-10T15:00:00.000Z"
                        }
                    ],
                    "source": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "source_url": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "type": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "value": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "title": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "type": [
                    {
                        "Comparison": "string",
                        "Value": "string"
                    }
                ],
                "updated_at": [
                    {
                        "date_range": {
                            "unit": "string",
                            "value": 20
                        },
                        "end": "2020-07-10T15:00:00.000Z",
                        "start": "2020-07-10T15:00:00.000Z"
                    }
                ],
                "user_defined_fields": [
                    {
                        "Comparison": "string",
                        "Key": "string",
                        "Value": "string"
                    }
                ],
                "verification": {
                    "state": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                },
                "workflow": {
                    "state": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ],
                    "status": [
                        {
                            "Comparison": "string",
                            "Value": "string"
                        }
                    ]
                }
            },
            "group_by_attribute": "string",
            "insight_arn": "string",
            "name": "string"
        }
    },
    "data_stream": {
        "dataset": "aws.securityhub_insights",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "eea1c0db-3657-4195-add3-da25a54834e7",
        "snapshot": true,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-07-27T12:48:31.384Z",
        "dataset": "aws.securityhub_insights",
        "ingested": "2022-07-27T12:48:34Z",
        "kind": "event",
        "original": "{\"Filters\":{\"AwsAccountId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"CompanyName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ComplianceStatus\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Confidence\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"CreatedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"Criticality\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"Description\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"FindingProviderFieldsConfidence\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"FindingProviderFieldsCriticality\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"FindingProviderFieldsRelatedFindingsId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"FindingProviderFieldsRelatedFindingsProductArn\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"FindingProviderFieldsSeverityLabel\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"FindingProviderFieldsSeverityOriginal\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"FindingProviderFieldsTypes\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"FirstObservedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"GeneratorId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Id\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Keyword\":[{\"Value\":\"string\"}],\"LastObservedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"MalwareName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"MalwarePath\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"MalwareState\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"MalwareType\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NetworkDestinationDomain\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NetworkDestinationIpV4\":[{\"Cidr\":\"string\"}],\"NetworkDestinationIpV6\":[{\"Cidr\":\"string\"}],\"NetworkDestinationPort\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"NetworkDirection\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NetworkProtocol\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NetworkSourceDomain\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NetworkSourceIpV4\":[{\"Cidr\":\"string\"}],\"NetworkSourceIpV6\":[{\"Cidr\":\"string\"}],\"NetworkSourceMac\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NetworkSourcePort\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"NoteText\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"NoteUpdatedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"NoteUpdatedBy\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ProcessLaunchedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"ProcessName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ProcessParentPid\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"ProcessPath\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ProcessPid\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"ProcessTerminatedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"ProductArn\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ProductFields\":[{\"Comparison\":\"string\",\"Key\":\"string\",\"Value\":\"string\"}],\"ProductName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"RecommendationText\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"RecordState\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Region\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"RelatedFindingsId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"RelatedFindingsProductArn\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsEc2InstanceIamInstanceProfileArn\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsEc2InstanceImageId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsEc2InstanceIpV4Addresses\":[{\"Cidr\":\"string\"}],\"ResourceAwsEc2InstanceIpV6Addresses\":[{\"Cidr\":\"string\"}],\"ResourceAwsEc2InstanceKeyName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsEc2InstanceLaunchedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"ResourceAwsEc2InstanceSubnetId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsEc2InstanceType\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsEc2InstanceVpcId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsIamAccessKeyCreatedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"ResourceAwsIamAccessKeyPrincipalName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsIamAccessKeyStatus\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsIamAccessKeyUserName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsIamUserUserName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsS3BucketOwnerId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceAwsS3BucketOwnerName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceContainerImageId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceContainerImageName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceContainerLaunchedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"ResourceContainerName\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceDetailsOther\":[{\"Comparison\":\"string\",\"Key\":\"string\",\"Value\":\"string\"}],\"ResourceId\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourcePartition\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceRegion\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ResourceTags\":[{\"Comparison\":\"string\",\"Key\":\"string\",\"Value\":\"string\"}],\"ResourceType\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Sample\":[{\"Value\":true}],\"SeverityLabel\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"SeverityNormalized\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"SeverityProduct\":[{\"Eq\":20,\"Gte\":20,\"Lte\":20}],\"SourceUrl\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ThreatIntelIndicatorCategory\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ThreatIntelIndicatorLastObservedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"ThreatIntelIndicatorSource\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ThreatIntelIndicatorSourceUrl\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ThreatIntelIndicatorType\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"ThreatIntelIndicatorValue\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Title\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"Type\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"UpdatedAt\":[{\"DateRange\":{\"Unit\":\"string\",\"Value\":20},\"End\":\"2020-07-10 15:00:00.000\",\"Start\":\"2020-07-10 15:00:00.000\"}],\"UserDefinedFields\":[{\"Comparison\":\"string\",\"Key\":\"string\",\"Value\":\"string\"}],\"VerificationState\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"WorkflowState\":[{\"Comparison\":\"string\",\"Value\":\"string\"}],\"WorkflowStatus\":[{\"Comparison\":\"string\",\"Value\":\"string\"}]},\"GroupByAttribute\":\"string\",\"InsightArn\":\"string\",\"Name\":\"string\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "aws_securityhub_insights"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.securityhub_insights.filters.aws_account_id | The Amazon Web Services account ID that a finding is generated in. | flattened |
| aws.securityhub_insights.filters.company.name | The name of the findings provider(company) that owns the solution(product) that generates findings. | flattened |
| aws.securityhub_insights.filters.compliance.status | Exclusive to findings that are generated as the result of a check run against a specific rule in a supported standard, such as CIS Amazon Web Services Foundations. Contains security standard-related finding details. | flattened |
| aws.securityhub_insights.filters.confidence | A finding's confidence. Confidence is defined as the likelihood that a finding accurately identifies the behavior or issue that it was intended to identify. | flattened |
| aws.securityhub_insights.filters.created_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.created_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.created_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.created_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.criticality | The level of importance assigned to the resources associated with the finding. | flattened |
| aws.securityhub_insights.filters.description | A finding's description. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.confidence | The finding provider value for the finding confidence. Confidence is defined as the likelihood that a finding accurately identifies the behavior or issue that it was intended to identify. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.criticality | The finding provider value for the level of importance assigned to the resources associated with the findings. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.related_findings.id | The finding identifier of a related finding that is identified by the finding provider. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.related_findings.product.arn | The ARN of the solution that generated a related finding that is identified by the finding provider. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.severity.label | The finding provider value for the severity label. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.severity.original | The finding provider's original value for the severity. | flattened |
| aws.securityhub_insights.filters.finding_provider_fields.types | One or more finding types that the finding provider assigned to the finding. Uses the format of namespace/category/classifier that classify a finding. | flattened |
| aws.securityhub_insights.filters.first_observed_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.first_observed_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.first_observed_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.first_observed_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.generator.id | The identifier for the solution-specific component(a discrete unit of logic) that generated a finding. In various security-findings providers' solutions, this generator can be called a rule, a check, a detector, a plugin, etc. | flattened |
| aws.securityhub_insights.filters.id | The security findings provider-specific identifier for a finding. | flattened |
| aws.securityhub_insights.filters.keyword | A keyword for a finding. | flattened |
| aws.securityhub_insights.filters.last_observed_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.last_observed_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.last_observed_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.last_observed_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.malware.name | The name of the malware that was observed. | flattened |
| aws.securityhub_insights.filters.malware.path | The filesystem path of the malware that was observed. | flattened |
| aws.securityhub_insights.filters.malware.state | The state of the malware that was observed. | flattened |
| aws.securityhub_insights.filters.malware.type | The type of the malware that was observed. | flattened |
| aws.securityhub_insights.filters.network.destination.domain | The destination domain of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.destination.ip.v4 | The destination IPv4 address of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.destination.ip.v6 | The destination IPv6 address of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.destination.port | The destination port of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.direction | Indicates the direction of network traffic associated with a finding. | flattened |
| aws.securityhub_insights.filters.network.protocol | The protocol of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.source.domain | The source domain of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.source.ip.v4 | The source IPv4 address of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.source.ip.v6 | The source IPv6 address of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.source.mac | The source media access control(MAC) address of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.network.source.port | The source port of network-related information about a finding. | flattened |
| aws.securityhub_insights.filters.note.text | The text of a note. | flattened |
| aws.securityhub_insights.filters.note.updated_at.by | The principal that created a note. | flattened |
| aws.securityhub_insights.filters.note.updated_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.note.updated_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.note.updated_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.note.updated_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.note.updated_by | The text of a note. | flattened |
| aws.securityhub_insights.filters.process.launched_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.process.launched_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.process.launched_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.process.launched_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.process.name | The name of the process. | flattened |
| aws.securityhub_insights.filters.process.parent.pid | The parent process ID. | flattened |
| aws.securityhub_insights.filters.process.path | The path to the process executable. | flattened |
| aws.securityhub_insights.filters.process.pid | The process ID. | flattened |
| aws.securityhub_insights.filters.process.terminated_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.process.terminated_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.process.terminated_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.process.terminated_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.product.arn | The ARN generated by Security Hub that uniquely identifies a third-party company(security findings provider) after this provider's product(solution that generates findings) is registered with Security Hub. | flattened |
| aws.securityhub_insights.filters.product.fields | A data type where security-findings providers can include additional solution-specific details that aren't part of the defined AwsSecurityFinding format. | flattened |
| aws.securityhub_insights.filters.product.name | The name of the solution(product) that generates findings. | flattened |
| aws.securityhub_insights.filters.recommendation_text | The recommendation of what to do about the issue described in a finding. | flattened |
| aws.securityhub_insights.filters.record_state | The updated record state for the finding. | flattened |
| aws.securityhub_insights.filters.region | The Region from which the finding was generated. | flattened |
| aws.securityhub_insights.filters.related_findings.id | The solution-generated identifier for a related finding. | flattened |
| aws.securityhub_insights.filters.related_findings.product.arn | The ARN of the solution that generated a related finding. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.iam_instance_profile.arn | The IAM profile ARN of the instance. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.image.id | The Amazon Machine Image(AMI) ID of the instance. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.ip.v4_addresses | The IPv4 addresses associated with the instance. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.ip.v6_addresses | The IPv6 addresses associated with the instance. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.key.name | The key name associated with the instance. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.launched_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.launched_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.launched_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.launched_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.subnet.id | The identifier of the subnet that the instance was launched in. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.type | The instance type of the instance. | flattened |
| aws.securityhub_insights.filters.resource.aws_ec2_instance.vpc.id | The identifier of the VPC that the instance was launched in. | flattened |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.created_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.created_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.created_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.created_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.principal.name | The name of the principal that is associated with an IAM access key. | flattened |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.status | The status of the IAM access key related to a finding. | flattened |
| aws.securityhub_insights.filters.resource.aws_iam_access_key.user.name | The user associated with the IAM access key related to a finding. | flattened |
| aws.securityhub_insights.filters.resource.aws_iam_user.user.name | The name of an IAM user. | flattened |
| aws.securityhub_insights.filters.resource.aws_s3_bucket.owner.id | The canonical user ID of the owner of the S3 bucket. | flattened |
| aws.securityhub_insights.filters.resource.aws_s3_bucket.owner.name | The display name of the owner of the S3 bucket. | flattened |
| aws.securityhub_insights.filters.resource.container.image.id | The identifier of the image related to a finding. | flattened |
| aws.securityhub_insights.filters.resource.container.image.name | The name of the image related to a finding. | flattened |
| aws.securityhub_insights.filters.resource.container.launched_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.resource.container.launched_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.resource.container.launched_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.resource.container.launched_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.resource.container.name | The name of the container related to a finding. | flattened |
| aws.securityhub_insights.filters.resource.details_other | The details of a resource that doesn't have a specific subfield for the resource type defined. | flattened |
| aws.securityhub_insights.filters.resource.id | The canonical identifier for the given resource type. | flattened |
| aws.securityhub_insights.filters.resource.partition | The canonical Amazon Web Services partition name that the Region is assigned to. | flattened |
| aws.securityhub_insights.filters.resource.region | The canonical Amazon Web Services external Region name where this resource is located. | flattened |
| aws.securityhub_insights.filters.resource.tags | A list of Amazon Web Services tags associated with a resource at the time the finding was processed. | flattened |
| aws.securityhub_insights.filters.resource.type | Specifies the type of the resource that details are provided for. | flattened |
| aws.securityhub_insights.filters.sample | Indicates whether or not sample findings are included in the filter results. | flattened |
| aws.securityhub_insights.filters.severity.label | The label of a finding's severity. | flattened |
| aws.securityhub_insights.filters.severity.normalized | The normalized severity of a finding. | flattened |
| aws.securityhub_insights.filters.severity.product | The native severity as defined by the security-findings provider's solution that generated the finding. | flattened |
| aws.securityhub_insights.filters.source_url | A URL that links to a page about the current finding in the security-findings provider's solution. | flattened |
| aws.securityhub_insights.filters.threat_intel_indicator.category | The category of a threat intelligence indicator. | flattened |
| aws.securityhub_insights.filters.threat_intel_indicator.last_observed_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.threat_intel_indicator.last_observed_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.threat_intel_indicator.last_observed_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.threat_intel_indicator.last_observed_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.threat_intel_indicator.source | The source of the threat intelligence. | flattened |
| aws.securityhub_insights.filters.threat_intel_indicator.source_url | The URL for more details from the source of the threat intelligence. | flattened |
| aws.securityhub_insights.filters.threat_intel_indicator.type | The type of a threat intelligence indicator. | flattened |
| aws.securityhub_insights.filters.threat_intel_indicator.value | The value of a threat intelligence indicator. | flattened |
| aws.securityhub_insights.filters.title | A finding's title. | flattened |
| aws.securityhub_insights.filters.type | A finding type in the format of namespace/category/classifier that classifies a finding. | flattened |
| aws.securityhub_insights.filters.updated_at.date_range.unit | A date range unit for the date filter. | keyword |
| aws.securityhub_insights.filters.updated_at.date_range.value | A date range value for the date filter. | long |
| aws.securityhub_insights.filters.updated_at.end | An end date for the date filter. | date |
| aws.securityhub_insights.filters.updated_at.start | A start date for the date filter. | date |
| aws.securityhub_insights.filters.user_defined_fields | A list of name/value string pairs associated with the finding. These are custom, user-defined fields added to a finding. | flattened |
| aws.securityhub_insights.filters.verification.state | The veracity of a finding. | flattened |
| aws.securityhub_insights.filters.workflow.state | The workflow state of a finding. | flattened |
| aws.securityhub_insights.filters.workflow.status | The status of the investigation into a finding. | flattened |
| aws.securityhub_insights.group_by_attribute | The grouping attribute for the insight's findings. Indicates how to group the matching findings, and identifies the type of item that the insight applies to. For example, if an insight is grouped by resource identifier, then the insight produces a list of resource identifiers. | keyword |
| aws.securityhub_insights.insight_arn | The ARN of a Security Hub insight. | keyword |
| aws.securityhub_insights.name | The name of a Security Hub insight. | keyword |
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| tags | List of keywords used to tag each event. | keyword |
