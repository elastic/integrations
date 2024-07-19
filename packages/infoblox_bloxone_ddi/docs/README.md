# Infoblox BloxOne DDI

The [Infoblox BloxOne DDI](https://www.infoblox.com/products/bloxone-ddi/) integration allows you to monitor DNS, DHCP and IP address management activity. DDI is the foundation of core network services that enables all communications over an IP-based network.

Use the Infoblox BloxOne DDI integration to collects and parses data from the REST APIs and then visualize that data in Kibana.

## Data streams

The Infoblox BloxOne DDI integration collects logs for three types of events: DHCP lease, DNS data and DNS config.

**DHCP Lease** is a Infoblox BloxOne DDI service that stores information about leases. See more details about its API [here](https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FDhcpLeases).

**DNS Config** is a Infoblox BloxOne DDI service that provides cloud-based DNS configuration with on-prem host serving DNS protocol. See more details about its API [here](https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FDnsConfig).

**DNS Data** is a Infoblox BloxOne DDI service providing primary authoritative zone support. DNS Data is authoritative for all DNS resource records and is acting as a primary DNS server. See more details about its API [here](https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FDnsData).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against `Infoblox BloxOne DDI API (v1)`.

## Setup

### To collect data from Infoblox BloxOne DDI APIs, the user must have API Key. To create an API key follow the below steps:

1. Log on to the Cloud Services Portal.
2. Go to **\<User_Name> -> User Profile**.
3. Go to **User API Keys** page.
4. Click **Create** to create a new API key. Specify the following:
    - **Name**: Specify the name of the key.
    - **Expires at**: Specify the expiry.
5. Click **Save & Close**. The API Access Key Generated dialog is shown.
6. Click **Copy**.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **Infoblox BloxOne DDI**.
3. Click on **Infoblox BloxOne DDI** integration from the search results.
4. Click on **Add Infoblox BloxOne DDI** button to add Infoblox BloxOne DDI integration.
5. Enable the Integration to collect logs via API.

## Logs Reference

### dhcp_lease

This is the `dhcp_lease` dataset.

#### Example

An example event for `dhcp_lease` looks as following:

```json
{
    "@timestamp": "2022-07-11T11:51:15.417Z",
    "agent": {
        "ephemeral_id": "2012f3f7-49dc-4448-bb3b-60ba7ba8a293",
        "hostname": "docker-fleet-agent",
        "id": "e0bb9c9c-c3ad-47d7-882c-5fff0f458160",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "client": {
        "user": {
            "id": "abc3212abc"
        }
    },
    "data_stream": {
        "dataset": "infoblox_bloxone_ddi.dhcp_lease",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e0bb9c9c-c3ad-47d7-882c-5fff0f458160",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2022-11-21T10:35:16.397Z",
        "dataset": "infoblox_bloxone_ddi.dhcp_lease",
        "end": "2022-07-11T11:51:15.417Z",
        "ingested": "2022-11-21T10:35:19Z",
        "kind": "event",
        "original": "{\"address\":\"81.2.69.192\",\"client_id\":\"abc3212abc\",\"ends\":\"2022-07-11T11:51:15.417Z\",\"fingerprint\":\"ab3213cbabab/abc23bca\",\"fingerprint_processed\":\"12abca32bca32abcd\",\"ha_group\":\"abc321cdcbda321\",\"hardware\":\"00:00:5E:00:53:00\",\"host\":\"admin\",\"hostname\":\"Host1\",\"iaid\":0,\"last_updated\":\"2022-07-11T11:51:15.417Z\",\"options\":{\"message\":\"Hello\"},\"preferred_lifetime\":\"2022-07-11T11:51:15.417Z\",\"protocol\":\"ip4\",\"space\":\"DHCP lease Space\",\"starts\":\"2022-07-14T11:51:15.417Z\",\"state\":\"used\",\"type\":\"DHCP lease Type\"}",
        "start": "2022-07-14T11:51:15.417Z",
        "type": [
            "protocol"
        ]
    },
    "host": {
        "hostname": "Host1",
        "name": "admin"
    },
    "infoblox_bloxone_ddi": {
        "dhcp_lease": {
            "address": "81.2.69.192",
            "client_id": "abc3212abc",
            "ends": "2022-07-11T11:51:15.417Z",
            "fingerprint": {
                "processed": "12abca32bca32abcd",
                "value": "ab3213cbabab/abc23bca"
            },
            "ha_group": "abc321cdcbda321",
            "hardware": "00-00-5E-00-53-00",
            "host": "admin",
            "hostname": "Host1",
            "iaid": 0,
            "last_updated": "2022-07-11T11:51:15.417Z",
            "options": {
                "message": "Hello"
            },
            "preferred_lifetime": "2022-07-11T11:51:15.417Z",
            "protocol": "ipv4",
            "space": "DHCP lease Space",
            "starts": "2022-07-14T11:51:15.417Z",
            "state": "used",
            "type": "DHCP lease Type"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "type": "ipv4"
    },
    "related": {
        "hosts": [
            "admin",
            "Host1"
        ],
        "ip": [
            "81.2.69.192"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "infoblox_bloxone_ddi-dhcp_lease"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.address | The IP address of the DHCP lease in the format "a.b.c.d". This address will be marked as leased in IPAM while the lease exists. | ip |
| infoblox_bloxone_ddi.dhcp_lease.client_id | The client ID of the DHCP lease. It might be empty. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.ends | The time when the DHCP lease will expire. | date |
| infoblox_bloxone_ddi.dhcp_lease.fingerprint.processed | Indicates if the DHCP lease has been fingerprinted. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.fingerprint.value | The DHCP fingerprint of the lease. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.ha_group | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.hardware | The hardware address of the DHCP lease. This specifies the MAC address of the network interface on which the lease will be used. It consists of six groups of two hex digits in lower-case separated by colons. For example, "aa:bb:cc:dd:ee:ff". | keyword |
| infoblox_bloxone_ddi.dhcp_lease.host | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.hostname | The client hostname of the DHCP lease. This specifies the host name that the DHCP client sends to the DHCP server using DHCP option 12. It is a fully qualified domain name, consisting of a series of labels separated by dots. For example, "www.infoblox.com". It might be empty. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.iaid | Identity Association Identifier (IAID) of the lease. Applicable only for DHCPv6. | long |
| infoblox_bloxone_ddi.dhcp_lease.last_updated | The time when the DHCP lease was last updated. | date |
| infoblox_bloxone_ddi.dhcp_lease.options | The DHCP options of the lease in JSON format. | flattened |
| infoblox_bloxone_ddi.dhcp_lease.preferred_lifetime | The preferred time when the DHCP lease should expire. Applicable only for DHCPv6. | date |
| infoblox_bloxone_ddi.dhcp_lease.protocol | Lease protocol type. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.space | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.starts | The time when the DHCP lease was issued. | date |
| infoblox_bloxone_ddi.dhcp_lease.state | The state of the DHCP lease. | keyword |
| infoblox_bloxone_ddi.dhcp_lease.type | Lease type. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### dns_config

This is the `dns_config` dataset.

#### Example

An example event for `dns_config` looks as following:

```json
{
    "@timestamp": "2022-07-15T06:55:25.978Z",
    "agent": {
        "ephemeral_id": "b27c2d34-9c98-4383-9177-e1181be3de40",
        "hostname": "docker-fleet-agent",
        "id": "e0bb9c9c-c3ad-47d7-882c-5fff0f458160",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "infoblox_bloxone_ddi.dns_config",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "answers": {
            "ttl": 350
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e0bb9c9c-c3ad-47d7-882c-5fff0f458160",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2022-07-15T06:55:25.978Z",
        "dataset": "infoblox_bloxone_ddi.dns_config",
        "id": "adv12rgfh",
        "ingested": "2022-11-21T10:36:06Z",
        "kind": "event",
        "original": "{\"add_edns_option_in_outgoing_query\":true,\"comment\":\"DNS Config Comment\",\"created_at\":\"2022-07-15T06:55:25.978Z\",\"custom_root_ns\":[{\"address\":\"81.2.69.192\",\"fqdn\":\"custom fqdn\",\"protocol_fqdn\":\"custom protocol fqdn\"}],\"custom_root_ns_enabled\":true,\"disabled\":true,\"dnssec_enable_validation\":true,\"dnssec_enabled\":true,\"dnssec_root_keys\":[{\"algorithm\":30,\"protocol_zone\":\"Dnssec root protocol zone\",\"public_key\":\"Dnssec root Public Key\",\"sep\":true,\"zone\":\"Dnssec root Zone\"}],\"dnssec_trust_anchors\":[{\"algorithm\":10,\"protocol_zone\":\"Dnssec trust protocol zone\",\"public_key\":\"Dnssec trust Public Key\",\"sep\":true,\"zone\":\"Dnssec trust zone\"}],\"dnssec_validate_expiry\":true,\"ecs_enabled\":true,\"ecs_forwarding\":true,\"ecs_prefix_v4\":22,\"ecs_prefix_v6\":33,\"ecs_zones\":[{\"access\":\"ecs zones access\",\"fqdn\":\"ecs zones fqdn\",\"protocol_fqdn\":\"ecs zones protocol fqdn\"}],\"edns_udp_size\":568,\"forwarders\":[{\"address\":\"81.2.69.192\",\"fqdn\":\"forwarders fqdn\",\"protocol_fqdn\":\"forwarders protocol fqdn\"}],\"forwarders_only\":true,\"gss_tsig_enabled\":true,\"id\":\"adv12rgfh\",\"inheritance_sources\":{\"add_edns_option_in_outgoing_query\":{\"action\":\"inherit\",\"display_name\":\"displaynameadd_edns_option_in_outgoing_query\",\"source\":\"sourceadd_edns_option_in_outgoing_query\",\"value\":true},\"custom_root_ns_block\":{\"action\":\"override\",\"display_name\":\"displaynamecustom_root_ns_block\",\"source\":\"sourcecustom_root_ns_block\",\"value\":{\"custom_root_ns\":[{\"address\":\"67.43.156.0\",\"fqdn\":\"fqdn_custom_root_ns\",\"protocol_fqdn\":\"protocolfqdn_custom_root_ns\"}],\"custom_root_ns_enabled\":true}},\"dnssec_validation_block\":{\"action\":\"inherit\",\"display_name\":\"displaynamednssec_validation_block\",\"source\":\"sourcednssec_validation_block\",\"value\":{\"dnssec_enable_validation\":true,\"dnssec_enabled\":true,\"dnssec_trust_anchors\":[{\"algorithm\":8,\"protocol_zone\":\"protocolzonednssec_trust_anchors\",\"public_key\":\"publickeydnssec_trust_anchors\",\"sep\":false,\"zone\":\"is3zone\"}],\"dnssec_validate_expiry\":true}},\"ecs_block\":{\"action\":\"inherit\",\"display_name\":\"displaynameecs_block\",\"source\":\"sourceecs_block\",\"value\":{\"ecs_enabled\":false,\"ecs_forwarding\":true,\"ecs_prefix_v4\":4,\"ecs_prefix_v6\":10,\"ecs_zones\":[{\"access\":\"inherit\",\"fqdn\":\"fqdnecs_block\",\"protocol_fqdn\":\"protocol_fqdnecs_block\"}]}},\"ecs_zones\":{\"action\":\"override\",\"display_name\":\"displaynameecs_zones\",\"source\":\"sourceecs_zones\",\"value\":{\"ecs_enabled\":false,\"ecs_forwarding\":true,\"ecs_prefix_v4\":4,\"ecs_prefix_v6\":12,\"ecs_zones\":[{\"access\":\"access_ecs_zones\",\"fqdn\":\"fqdn_ecs_zones\",\"protocol_fqdn\":\"protocolfqdn_ecs_zones\"}]}},\"edns_udp_size\":{\"action\":\"inherit\",\"display_name\":\"displaynameedns_udp_size\",\"source\":\"sourceedns_udp_size\",\"value\":55},\"forwarders_block\":{\"action\":\"inherit\",\"display_name\":\"displaynameforwarders_block\",\"source\":\"sourceforwarders_block\",\"value\":{\"forwarders\":[{\"address\":\"89.160.20.128\",\"fqdn\":\"forwarders_fqdn\",\"protocol_fqdn\":\"forwarders_protocolfqdn\"}],\"forwarders_only\":true}},\"gss_tsig_enabled\":{\"action\":\"inherit\",\"display_name\":\"displaynamegss_tsig_enabled\",\"source\":\"sourcegss_tsig_enabled\",\"value\":true},\"lame_ttl\":{\"action\":\"inherit\",\"display_name\":\"displaynamelame_ttl\",\"source\":\"sourcelame_ttl\",\"value\":45},\"match_recursive_only\":{\"action\":\"inherit\",\"display_name\":\"displaynamematch_recursive_only\",\"source\":\"sourcematch_recursive_only\",\"value\":false},\"max_cache_ttl\":{\"action\":\"inherit\",\"display_name\":\"displaynamemax_cache_ttl\",\"source\":\"sourcemax_cache_ttl\",\"value\":13},\"max_negative_ttl\":{\"action\":\"inherit\",\"display_name\":\"displaynamemax_negative_ttl\",\"source\":\"sourcemax_negative_ttl\",\"value\":12},\"max_udp_size\":{\"action\":\"inherit\",\"display_name\":\"displaynamemax_udp_size\",\"source\":\"sourcemax_udp_size\",\"value\":11},\"minimal_responses\":{\"action\":\"inherit\",\"display_name\":\"displaynameminimal_responses\",\"source\":\"sourceminimal_responses\",\"value\":true},\"notify\":{\"action\":\"inherit\",\"display_name\":\"displayname_notify\",\"source\":\"source_notify\",\"value\":true},\"query_acl\":{\"action\":\"override\",\"display_name\":\"displaynamequery_acl\",\"source\":\"sourcequery_acl\",\"value\":[{\"access\":\"allow\",\"acl\":\"aclvalue_query_acl\",\"address\":\"89.160.20.128\",\"element\":\"elementvaluequery_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha256\",\"comment\":\"commentquery_acl\",\"key\":\"keyquery_acl\",\"name\":\"namequery_acl\",\"protocol_name\":\"protocolname_query_acl\",\"secret\":\"secretquery_acl\"}}]},\"recursion_acl\":{\"action\":\"override\",\"display_name\":\"displaynamerecursion_acl\",\"source\":\"sourcerecursion_acl\",\"value\":[{\"access\":\"deny\",\"acl\":\"aclrecursion_acl\",\"address\":\"89.160.20.128\",\"element\":\"elementrecursion_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha384\",\"comment\":\"commentrecursion_acl\",\"key\":\"keyrecursion_acl\",\"name\":\"namerecursion_acl\",\"protocol_name\":\"protocolnamerecursion_acl\",\"secret\":\"secretrecursion_acl\"}}]},\"recursion_enabled\":{\"action\":\"inherit\",\"display_name\":\"displaynamerecursion_enabled\",\"source\":\"sourcerecursion_enabled\",\"value\":true},\"synthesize_address_records_from_https\":{\"action\":\"inherit\",\"display_name\":\"displaynamesynthesize_address_records_from_https\",\"source\":\"sourcesynthesize_address_records_from_https\",\"value\":true},\"transfer_acl\":{\"action\":\"inherit\",\"display_name\":\"displaynametransfer_acl\",\"source\":\"sourcetransfer_acl\",\"value\":[{\"access\":\"allow\",\"acl\":\"acltransfer_acl\",\"address\":\"216.160.83.56\",\"element\":\"elementtransfer_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha224\",\"comment\":\"commenttransfer_acl\",\"key\":\"keytransfer_acl\",\"name\":\"nametransfer_acl\",\"protocol_name\":\"protocolnametransfer_acl\",\"secret\":\"secrettransfer_acl\"}}]},\"update_acl\":{\"action\":\"override\",\"display_name\":\"displaynameupdate_acl\",\"source\":\"sourceupdate_acl\",\"value\":[{\"access\":\"allow\",\"acl\":\"aclupdate_acl\",\"address\":\"216.160.83.56\",\"element\":\"elementupdate_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha384\",\"comment\":\"commentupdate_acl\",\"key\":\"keyupdate_acl\",\"name\":\"nameupdate_acl\",\"protocol_name\":\"protocolnameupdate_acl\",\"secret\":\"secretupdate_acl\"}}]},\"use_forwarders_for_subzones\":{\"action\":\"override\",\"display_name\":\"displaynameuse_forwarders_for_subzones\",\"source\":\"sourceuse_forwarders_for_subzones\",\"value\":false},\"zone_authority\":{\"default_ttl\":{\"action\":\"override\",\"display_name\":\"displaynamezone_authority\",\"source\":\"sourcezone_authority\",\"value\":50},\"expire\":{\"action\":\"inherit\",\"display_name\":\"displaynameexpire\",\"source\":\"sourceexpire\",\"value\":70},\"mname_block\":{\"action\":\"inherit\",\"display_name\":\"displaynamemname_block\",\"source\":\"sourcemname_block\",\"value\":{\"mname\":\"mnamevaluemname_block\",\"protocol_mname\":\"protocolmnamemname_block\",\"use_default_mname\":true}},\"negative_ttl\":{\"action\":\"inherit\",\"display_name\":\"displaynamenegative_ttl\",\"source\":\"sourcenegative_ttl\",\"value\":90},\"protocol_rname\":{\"action\":\"inherit\",\"display_name\":\"displaynameprotocol_rname\",\"source\":\"sourceprotocol_rname\",\"value\":\"valueprotocol_rname\"},\"refresh\":{\"action\":\"inherit\",\"display_name\":\"displayname_refresh\",\"source\":\"source_refresh\",\"value\":40},\"retry\":{\"action\":\"inherit\",\"display_name\":\"displayname_retry\",\"source\":\"source_retry\",\"value\":570},\"rname\":{\"action\":\"inherit\",\"display_name\":\"displayname_rname\",\"source\":\"source_rname\",\"value\":\"value_rname\"}}},\"ip_spaces\":[\"testipspaces\"],\"lame_ttl\":350,\"match_clients_acl\":[{\"access\":\"deny\",\"acl\":\"aclmatch_clients_acl\",\"address\":\"81.2.69.192\",\"element\":\"elementmatch_clients_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha512\",\"comment\":\"commentmatch_clients_acl\",\"key\":\"keymatch_clients_acl\",\"name\":\"namematch_clients_acl\",\"protocol_name\":\"protocolnamematch_clients_acl\",\"secret\":\"secretmatch_clients_acl\"}}],\"match_destinations_acl\":[{\"access\":\"allow\",\"acl\":\"aclmatch_destinations_acl\",\"address\":\"81.2.69.192\",\"element\":\"elementmatch_destinations_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha384\",\"comment\":\"commentmatch_destinations_acl\",\"key\":\"keymatch_destinations_acl\",\"name\":\"namematch_destinations_acl\",\"protocol_name\":\"protocolnamematch_destinations_acl\",\"secret\":\"secretmatch_destinations_acl\"}}],\"match_recursive_only\":true,\"max_cache_ttl\":90,\"max_negative_ttl\":500,\"max_udp_size\":890,\"minimal_responses\":true,\"name\":\"string\",\"notify\":true,\"query_acl\":[{\"access\":\"accessquery_acl\",\"acl\":\"aclquery_acl\",\"address\":\"81.2.69.192\",\"element\":\"elementquery_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha224\",\"comment\":\"commentquery_acl\",\"key\":\"keyquery_acl\",\"name\":\"namequery_acl\",\"protocol_name\":\"protocolnamequery_acl\",\"secret\":\"secretquery_acl\"}}],\"recursion_acl\":[{\"access\":\"allow\",\"acl\":\"aclrecursion_acl\",\"address\":\"81.2.69.192\",\"element\":\"elementrecursion_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha1\",\"comment\":\"commentrecursion_acl\",\"key\":\"keyrecursion_acl\",\"name\":\"namerecursion_acl\",\"protocol_name\":\"protocolnamerecursion_acl\",\"secret\":\"secretrecursion_acl\"}}],\"recursion_enabled\":true,\"synthesize_address_records_from_https\":false,\"tags\":{\"message\":\"Hello\"},\"transfer_acl\":[{\"access\":\"allow\",\"acl\":\"acltransfer_acl\",\"address\":\"216.160.83.56\",\"element\":\"elementtransfer_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha224\",\"comment\":\"commenttransfer_acl\",\"key\":\"keytransfer_acl\",\"name\":\"nametransfer_acl\",\"protocol_name\":\"protocolnametransfer_acl\",\"secret\":\"secrettransfer_acl\"}}],\"update_acl\":[{\"access\":\"allow\",\"acl\":\"aclupdate_acl\",\"address\":\"216.160.83.56\",\"element\":\"elementupdate_acl\",\"tsig_key\":{\"algorithm\":\"hmac_sha1\",\"comment\":\"commentupdate_acl\",\"key\":\"keyupdate_acl\",\"name\":\"nameupdate_acl\",\"protocol_name\":\"protocolnameupdate_acl\",\"secret\":\"secretupdate_acl\"}}],\"updated_at\":\"2022-07-15T06:55:25.978Z\",\"use_forwarders_for_subzones\":true,\"zone_authority\":{\"default_ttl\":20,\"expire\":10,\"mname\":\"mnamezone_authority\",\"negative_ttl\":30,\"protocol_mname\":\"protocolmnamezone_authority\",\"protocol_rname\":\"protocolrnamezone_authority\",\"refresh\":50,\"retry\":100,\"rname\":\"string\",\"use_default_mname\":true}}",
        "type": [
            "protocol"
        ]
    },
    "infoblox_bloxone_ddi": {
        "dns_config": {
            "add_edns": {
                "option_in": {
                    "outgoing_query": true
                }
            },
            "comment": "DNS Config Comment",
            "created_at": "2022-07-15T06:55:25.978Z",
            "custom_root_ns": [
                {
                    "address": "81.2.69.192",
                    "fqdn": "custom fqdn",
                    "protocol": {
                        "fqdn": "custom protocol fqdn"
                    }
                }
            ],
            "custom_root_ns_enabled": true,
            "disabled": true,
            "dnssec": {
                "enable_validation": true,
                "enabled": true,
                "root_keys": [
                    {
                        "algorithm": 30,
                        "protocol": {
                            "zone": "Dnssec root protocol zone"
                        },
                        "public": "Dnssec root Public Key",
                        "sep": true,
                        "zone": "Dnssec root Zone"
                    }
                ],
                "trust_anchors": [
                    {
                        "algorithm": 10,
                        "protocol": {
                            "zone": "Dnssec trust protocol zone"
                        },
                        "public_key": "Dnssec trust Public Key",
                        "sep": true,
                        "zone": "Dnssec trust zone"
                    }
                ],
                "validate_expiry": true
            },
            "ecs": {
                "enabled": true,
                "forwarding": true,
                "prefix_v4": 22,
                "prefix_v6": 33,
                "zones": [
                    {
                        "access": "ecs zones access",
                        "fqdn": "ecs zones fqdn",
                        "protocol": {
                            "fqdn": "ecs zones protocol fqdn"
                        }
                    }
                ]
            },
            "edns": {
                "udp": {
                    "size": 568
                }
            },
            "forwarders": [
                {
                    "address": "81.2.69.192",
                    "fqdn": "forwarders fqdn",
                    "protocol": {
                        "fqdn": "forwarders protocol fqdn"
                    }
                }
            ],
            "forwarders_only": true,
            "gss_tsig_enabled": true,
            "id": "adv12rgfh",
            "inheritance": {
                "sources": {
                    "add_edns": {
                        "option_in": {
                            "outgoing_query": {
                                "action": "inherit",
                                "display": {
                                    "name": "displaynameadd_edns_option_in_outgoing_query"
                                },
                                "source": "sourceadd_edns_option_in_outgoing_query",
                                "value": true
                            }
                        }
                    },
                    "custom_root_ns": {
                        "block": {
                            "action": "override",
                            "display": {
                                "name": "displaynamecustom_root_ns_block"
                            },
                            "source": "sourcecustom_root_ns_block",
                            "value": [
                                {
                                    "address": "67.43.156.0",
                                    "fqdn": "fqdn_custom_root_ns",
                                    "protocol": {
                                        "fqdn": "protocolfqdn_custom_root_ns"
                                    }
                                }
                            ],
                            "value_enabled": true
                        }
                    },
                    "dnssec": {
                        "validation": {
                            "block": {
                                "action": "inherit",
                                "display": {
                                    "name": "displaynamednssec_validation_block"
                                },
                                "source": "sourcednssec_validation_block",
                                "value": {
                                    "enable": true,
                                    "enabled": true,
                                    "trust_anchors": [
                                        {
                                            "algorithm": 8,
                                            "protocol": {
                                                "zone": "protocolzonednssec_trust_anchors"
                                            },
                                            "public_key": "publickeydnssec_trust_anchors",
                                            "sep": false,
                                            "zone": "is3zone"
                                        }
                                    ],
                                    "validate_expiry": true
                                }
                            }
                        }
                    },
                    "ecs": {
                        "block": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynameecs_block"
                            },
                            "source": "sourceecs_block",
                            "value": {
                                "enabled": false,
                                "forwarding": true,
                                "prefix_v4": 4,
                                "prefix_v6": 10,
                                "zones": [
                                    {
                                        "access": "inherit",
                                        "fqdn": "fqdnecs_block",
                                        "protocol": {
                                            "fqdn": "protocol_fqdnecs_block"
                                        }
                                    }
                                ]
                            }
                        }
                    },
                    "edns": {
                        "udp": {
                            "size": {
                                "action": "inherit",
                                "display": {
                                    "name": "displaynameedns_udp_size"
                                },
                                "source": "sourceedns_udp_size",
                                "value": 55
                            }
                        }
                    },
                    "forwarders": {
                        "block": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynameforwarders_block"
                            },
                            "source": "sourceforwarders_block",
                            "value": [
                                {
                                    "address": "89.160.20.128",
                                    "fqdn": "forwarders_fqdn",
                                    "protocol": {
                                        "fqdn": "forwarders_protocolfqdn"
                                    }
                                }
                            ],
                            "value_only": true
                        }
                    },
                    "gss_tsig_enabled": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamegss_tsig_enabled"
                        },
                        "source": "sourcegss_tsig_enabled",
                        "value": true
                    },
                    "lame_ttl": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamelame_ttl"
                        },
                        "source": "sourcelame_ttl",
                        "value": 45
                    },
                    "match_recursive_only": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamematch_recursive_only"
                        },
                        "source": "sourcematch_recursive_only",
                        "value": false
                    },
                    "max_cache_ttl": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamemax_cache_ttl"
                        },
                        "source": "sourcemax_cache_ttl",
                        "value": 13
                    },
                    "max_negative_ttl": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamemax_negative_ttl"
                        },
                        "source": "sourcemax_negative_ttl",
                        "value": 12
                    },
                    "max_udp_size": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamemax_udp_size"
                        },
                        "source": "sourcemax_udp_size",
                        "value": 11
                    },
                    "minimal_responses": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynameminimal_responses"
                        },
                        "source": "sourceminimal_responses",
                        "value": true
                    },
                    "notify": {
                        "action": "inherit",
                        "display": {
                            "name": "displayname_notify"
                        },
                        "source": "source_notify",
                        "value": true
                    },
                    "query_acl": {
                        "action": "override",
                        "display": {
                            "name": "displaynamequery_acl"
                        },
                        "source": "sourcequery_acl",
                        "value": [
                            {
                                "access": "allow",
                                "acl": "aclvalue_query_acl",
                                "address": "89.160.20.128",
                                "element": "elementvaluequery_acl",
                                "tsig_key": {
                                    "algorithm": "hmac_sha256",
                                    "comment": "commentquery_acl",
                                    "key": "keyquery_acl",
                                    "name": "namequery_acl",
                                    "protocol": {
                                        "name": "protocolname_query_acl"
                                    },
                                    "secret": "secretquery_acl"
                                }
                            }
                        ]
                    },
                    "recursion_acl": {
                        "action": "override",
                        "display": {
                            "name": "displaynamerecursion_acl"
                        },
                        "source": "sourcerecursion_acl",
                        "value": [
                            {
                                "access": "deny",
                                "acl": "aclrecursion_acl",
                                "address": "89.160.20.128",
                                "element": "elementrecursion_acl",
                                "tsig_key": {
                                    "algorithm": "hmac_sha384",
                                    "comment": "commentrecursion_acl",
                                    "key": "keyrecursion_acl",
                                    "name": "namerecursion_acl",
                                    "protocol": {
                                        "name": "protocolnamerecursion_acl"
                                    },
                                    "secret": "secretrecursion_acl"
                                }
                            }
                        ]
                    },
                    "recursion_enabled": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynamerecursion_enabled"
                        },
                        "source": "sourcerecursion_enabled",
                        "value": true
                    },
                    "synthesize": {
                        "address_records_from_https": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynamesynthesize_address_records_from_https"
                            },
                            "name": "sourcesynthesize_address_records_from_https",
                            "value": true
                        }
                    },
                    "transfer_acl": {
                        "action": "inherit",
                        "display": {
                            "name": "displaynametransfer_acl"
                        },
                        "source": "sourcetransfer_acl",
                        "value": [
                            {
                                "access": "allow",
                                "acl": "acltransfer_acl",
                                "address": "216.160.83.56",
                                "element": "elementtransfer_acl",
                                "tsig_key": {
                                    "algorithm": "hmac_sha224",
                                    "comment": "commenttransfer_acl",
                                    "key": "keytransfer_acl",
                                    "name": "nametransfer_acl",
                                    "protocol": {
                                        "name": "protocolnametransfer_acl"
                                    },
                                    "secret": "secrettransfer_acl"
                                }
                            }
                        ]
                    },
                    "update_acl": {
                        "action": "override",
                        "display": {
                            "name": "displaynameupdate_acl"
                        },
                        "source": "sourceupdate_acl",
                        "value": [
                            {
                                "access": "allow",
                                "acl": "aclupdate_acl",
                                "address": "216.160.83.56",
                                "element": "elementupdate_acl",
                                "tsig_key": {
                                    "algorithm": "hmac_sha384",
                                    "comment": "commentupdate_acl",
                                    "key": "keyupdate_acl",
                                    "name": "nameupdate_acl",
                                    "protocol": {
                                        "name": "protocolnameupdate_acl"
                                    },
                                    "secret": "secretupdate_acl"
                                }
                            }
                        ]
                    },
                    "use_forwarders_for_subzones": {
                        "action": "override",
                        "display": {
                            "name": "displaynameuse_forwarders_for_subzones"
                        },
                        "source": "sourceuse_forwarders_for_subzones",
                        "value": false
                    },
                    "zone_authority": {
                        "default_ttl": {
                            "action": "override",
                            "display": {
                                "name": "displaynamezone_authority"
                            },
                            "source": "sourcezone_authority",
                            "value": 50
                        },
                        "expire": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynameexpire"
                            },
                            "source": "sourceexpire",
                            "value": 70
                        },
                        "mname_block": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynamemname_block"
                            },
                            "source": "sourcemname_block",
                            "value": {
                                "isdefault": true,
                                "protocol": {
                                    "mname": "protocolmnamemname_block"
                                }
                            }
                        },
                        "mname_block_value": "mnamevaluemname_block",
                        "negative_ttl": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynamenegative_ttl"
                            },
                            "source": "sourcenegative_ttl",
                            "value": 90
                        },
                        "protocol_rname": {
                            "action": "inherit",
                            "display": {
                                "name": "displaynameprotocol_rname"
                            },
                            "source": "sourceprotocol_rname",
                            "value": "valueprotocol_rname"
                        },
                        "refresh": {
                            "action": "inherit",
                            "display": {
                                "name": "displayname_refresh"
                            },
                            "source": "source_refresh",
                            "value": 40
                        },
                        "retry": {
                            "action": "inherit",
                            "display": {
                                "name": "displayname_retry"
                            },
                            "source": "source_retry",
                            "value": 570
                        },
                        "rname": {
                            "action": "inherit",
                            "display": {
                                "name": "displayname_rname"
                            },
                            "source": "source_rname",
                            "value": "value_rname"
                        }
                    }
                }
            },
            "ip_spaces": [
                "testipspaces"
            ],
            "lame_ttl": 350,
            "match_clients_acl": [
                {
                    "access": "deny",
                    "address": "81.2.69.192",
                    "element": "elementmatch_clients_acl",
                    "tsig_key": {
                        "algorithm": "hmac_sha512",
                        "comment": "commentmatch_clients_acl",
                        "key": "keymatch_clients_acl",
                        "name": "namematch_clients_acl",
                        "protocol": {
                            "name": "protocolnamematch_clients_acl"
                        },
                        "secret": "secretmatch_clients_acl"
                    },
                    "value": "aclmatch_clients_acl"
                }
            ],
            "match_destinations_acl": [
                {
                    "access": "allow",
                    "address": "81.2.69.192",
                    "element": "elementmatch_destinations_acl",
                    "tsig_key": {
                        "algorithm": "hmac_sha384",
                        "comment": "commentmatch_destinations_acl",
                        "key": "keymatch_destinations_acl",
                        "name": "namematch_destinations_acl",
                        "protocol": {
                            "name": "protocolnamematch_destinations_acl"
                        },
                        "secret": "secretmatch_destinations_acl"
                    },
                    "value": "aclmatch_destinations_acl"
                }
            ],
            "match_recursive_only": true,
            "max_cache_ttl": 90,
            "max_negative_ttl": 500,
            "max_udp_size": 890,
            "minimal_responses": true,
            "name": "string",
            "notify": true,
            "query_acl": [
                {
                    "access": "accessquery_acl",
                    "address": "81.2.69.192",
                    "element": "elementquery_acl",
                    "tsig_key": {
                        "algorithm": "hmac_sha224",
                        "comment": "commentquery_acl",
                        "key": "keyquery_acl",
                        "name": "namequery_acl",
                        "protocol": {
                            "name": "protocolnamequery_acl"
                        },
                        "secret": "secretquery_acl"
                    },
                    "value": "aclquery_acl"
                }
            ],
            "recursion_acl": [
                {
                    "access": "allow",
                    "address": "81.2.69.192",
                    "element": "elementrecursion_acl",
                    "tsig_key": {
                        "algorithm": "hmac_sha1",
                        "comment": "commentrecursion_acl",
                        "key": "keyrecursion_acl",
                        "name": "namerecursion_acl",
                        "protocol": {
                            "name": "protocolnamerecursion_acl"
                        },
                        "secret": "secretrecursion_acl"
                    },
                    "value": "aclrecursion_acl"
                }
            ],
            "recursion_enabled": true,
            "synthesize": {
                "address_records_from_https": false
            },
            "tags": {
                "message": "Hello"
            },
            "transfer_acl": [
                {
                    "access": "allow",
                    "address": "216.160.83.56",
                    "element": "elementtransfer_acl",
                    "tsig_key": {
                        "algorithm": "hmac_sha224",
                        "comment": "commenttransfer_acl",
                        "key": "keytransfer_acl",
                        "name": "nametransfer_acl",
                        "protocol": {
                            "name": "protocolnametransfer_acl"
                        },
                        "secret": "secrettransfer_acl"
                    },
                    "value": "acltransfer_acl"
                }
            ],
            "update_acl": [
                {
                    "access": "allow",
                    "address": "216.160.83.56",
                    "element": "elementupdate_acl",
                    "tsig_key": {
                        "algorithm": "hmac_sha1",
                        "comment": "commentupdate_acl",
                        "key": "keyupdate_acl",
                        "name": "nameupdate_acl",
                        "protocol": {
                            "name": "protocolnameupdate_acl"
                        },
                        "secret": "secretupdate_acl"
                    },
                    "value": "aclupdate_acl"
                }
            ],
            "updated_at": "2022-07-15T06:55:25.978Z",
            "use_forwarders_for_subzones": true,
            "zone_authority": {
                "default_ttl": 20,
                "expire": 10,
                "mname": "mnamezone_authority",
                "negative_ttl": 30,
                "protocol": {
                    "mname": "protocolmnamezone_authority",
                    "rname": "protocolrnamezone_authority"
                },
                "refresh": 50,
                "retry": 100,
                "rname": "string",
                "use_default_mname": true
            }
        }
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "hash": [
            "hmac_sha256",
            "hmac_sha384",
            "hmac_sha224",
            "hmac_sha512",
            "hmac_sha1"
        ],
        "ip": [
            "81.2.69.192",
            "67.43.156.0",
            "89.160.20.128",
            "216.160.83.56"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "infoblox_bloxone_ddi-dns_config"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| infoblox_bloxone_ddi.dns_config.add_edns.option_in.outgoing_query | add_edns_option_in_outgoing_query adds client IP, MAC address and view name into outgoing recursive query. | boolean |
| infoblox_bloxone_ddi.dns_config.comment | Optional. Comment for view. | keyword |
| infoblox_bloxone_ddi.dns_config.created_at | The timestamp when the object has been created. | date |
| infoblox_bloxone_ddi.dns_config.custom_root_ns.address | IPv4 address. | ip |
| infoblox_bloxone_ddi.dns_config.custom_root_ns.fqdn | FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.custom_root_ns.protocol.fqdn | FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.custom_root_ns_enabled | Optional. true to use custom root nameservers instead of the default ones. | boolean |
| infoblox_bloxone_ddi.dns_config.disabled | Optional. true to disable object. A disabled object is effectively non-existent when generating configuration. | boolean |
| infoblox_bloxone_ddi.dns_config.dnssec.enable_validation | Optional. true to perform DNSSEC validation. | boolean |
| infoblox_bloxone_ddi.dns_config.dnssec.enabled | Optional. Master toggle for all DNSSEC processing. | boolean |
| infoblox_bloxone_ddi.dns_config.dnssec.root_keys.algorithm | Key algorithm. Algorithm values are as per standards. | long |
| infoblox_bloxone_ddi.dns_config.dnssec.root_keys.protocol.zone | Zone FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.dnssec.root_keys.public | DNSSEC key data. Non-empty, valid base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.dnssec.root_keys.sep | Optional. Secure Entry Point flag. | boolean |
| infoblox_bloxone_ddi.dns_config.dnssec.root_keys.zone | Zone FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.dnssec.trust_anchors.algorithm | Key algorithm. Algorithm values are as per standards. | long |
| infoblox_bloxone_ddi.dns_config.dnssec.trust_anchors.protocol.zone | Zone FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.dnssec.trust_anchors.public_key | DNSSEC key data. Non-empty, valid base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.dnssec.trust_anchors.sep | Optional. Secure Entry Point flag. | boolean |
| infoblox_bloxone_ddi.dns_config.dnssec.trust_anchors.zone | Zone FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.dnssec.validate_expiry | Optional. true to reject expired DNSSEC keys. | boolean |
| infoblox_bloxone_ddi.dns_config.ecs.enabled | Optional. true to enable EDNS client subnet for recursive queries. | boolean |
| infoblox_bloxone_ddi.dns_config.ecs.forwarding | Optional. true to enable ECS options in outbound queries. This functionality has additional overhead so it is disabled by default. | boolean |
| infoblox_bloxone_ddi.dns_config.ecs.prefix_v4 | Optional. Maximum scope length for v4 ECS. | long |
| infoblox_bloxone_ddi.dns_config.ecs.prefix_v6 | Optional. Maximum scope length for v6 ECS. | long |
| infoblox_bloxone_ddi.dns_config.ecs.zones.access | Access control for zone. | keyword |
| infoblox_bloxone_ddi.dns_config.ecs.zones.fqdn | Zone FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.ecs.zones.protocol.fqdn | Zone FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.edns.udp.size | Optional. edns_udp_size represents the edns UDP size. | long |
| infoblox_bloxone_ddi.dns_config.forwarders.address | Server IP address. | ip |
| infoblox_bloxone_ddi.dns_config.forwarders.fqdn | Server FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.forwarders.protocol.fqdn | Server FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.forwarders_only | Optional. true to only forward. | boolean |
| infoblox_bloxone_ddi.dns_config.gss_tsig_enabled | gss_tsig_enabled enables/disables GSS-TSIG signed dynamic updates. | boolean |
| infoblox_bloxone_ddi.dns_config.id | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.add_edns.option_in.outgoing_query.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.add_edns.option_in.outgoing_query.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.add_edns.option_in.outgoing_query.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.add_edns.option_in.outgoing_query.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.action | Defaults to inherit. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.display.name | Human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.value.address | IPv4 address. | ip |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.value.fqdn | Optional. Field config for custom_root_ns_enabled field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.value.protocol.fqdn | FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.custom_root_ns.block.value_enabled | FQDN in punycode. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.action | Defaults to inherit. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.display.name | Human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.enable | Optional. Field config for dnssec_enable_validation field. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.enabled | Optional. Field config for dnssec_enabled field. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.trust_anchors.algorithm | Key algorithm. Algorithm values are as per standards. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.trust_anchors.protocol.zone | Zone FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.trust_anchors.public_key | DNSSEC key data. Non-empty, valid base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.trust_anchors.sep | Optional. Secure Entry Point flag. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.trust_anchors.zone | Zone FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.dnssec.validation.block.value.validate_expiry | Optional. Field config for dnssec_validate_expiry field. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.action | Defaults to inherit. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.display.name | Human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.enabled | Optional. Field config for ecs_enabled field. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.forwarding | Optional. Field config for ecs_forwarding field. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.prefix_v4 | Optional. Field config for ecs_prefix_v4 field. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.prefix_v6 | Optional. Field config for ecs_prefix_v6 field. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.zones.access | Access control for zone. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.zones.fqdn | Zone FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.ecs.block.value.zones.protocol.fqdn | Zone FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.edns.udp.size.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.edns.udp.size.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.edns.udp.size.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.edns.udp.size.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.action | Defaults to inherit. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.display.name | Human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.value.address | Server IP address. | ip |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.value.fqdn | Server FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.value.protocol.fqdn | Server FQDN in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.forwarders.block.value_only | Optional. Field config for forwarders_only field. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.gss_tsig_enabled.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.gss_tsig_enabled.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.gss_tsig_enabled.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.gss_tsig_enabled.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.lame_ttl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.lame_ttl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.lame_ttl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.lame_ttl.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.match_recursive_only.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.match_recursive_only.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.match_recursive_only.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.match_recursive_only.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_cache_ttl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_cache_ttl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_cache_ttl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_cache_ttl.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_negative_ttl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_negative_ttl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_negative_ttl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_negative_ttl.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_udp_size.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_udp_size.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_udp_size.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.max_udp_size.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.minimal_responses.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.minimal_responses.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.minimal_responses.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.minimal_responses.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.notify.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.notify.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.notify.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.notify.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.acl | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.query_acl.value.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.acl | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_acl.value.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_enabled.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_enabled.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_enabled.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.recursion_enabled.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.synthesize.address_records_from_https.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.synthesize.address_records_from_https.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.synthesize.address_records_from_https.name | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.synthesize.address_records_from_https.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.acl | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.transfer_acl.value.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.acl | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.update_acl.value.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.use_forwarders_for_subzones.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.use_forwarders_for_subzones.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.use_forwarders_for_subzones.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.use_forwarders_for_subzones.value | The inherited value. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.default_ttl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.default_ttl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.default_ttl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.default_ttl.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.expire.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.expire.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.expire.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.expire.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.mname_block.action | Defaults to inherit. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.mname_block.display.name | Human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.mname_block.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.mname_block.value.isdefault | Optional. Use default value for master name server. Defaults to true. | boolean |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.mname_block.value.protocol.mname | Optional. Master name server in punycode. Defaults to empty. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.mname_block_value | Defaults to empty. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.negative_ttl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.negative_ttl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.negative_ttl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.negative_ttl.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.protocol_rname.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.protocol_rname.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.protocol_rname.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.protocol_rname.value | The inherited value. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.refresh.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.refresh.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.refresh.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.refresh.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.retry.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.retry.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.retry.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.retry.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.rname.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.rname.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.rname.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.inheritance.sources.zone_authority.rname.value | The inherited value. | keyword |
| infoblox_bloxone_ddi.dns_config.ip_spaces | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.lame_ttl | Optional. Unused in the current on-prem DNS server implementation. | long |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.match_clients_acl.value | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.match_destinations_acl.value | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.match_recursive_only | Optional. If true only recursive queries from matching clients access the view. | boolean |
| infoblox_bloxone_ddi.dns_config.max_cache_ttl | Optional. Seconds to cache positive responses. | long |
| infoblox_bloxone_ddi.dns_config.max_negative_ttl | Optional. Seconds to cache negative responses. | long |
| infoblox_bloxone_ddi.dns_config.max_udp_size | Optional. max_udp_size represents maximum UDP payload size. | long |
| infoblox_bloxone_ddi.dns_config.minimal_responses | Optional. When enabled, the DNS server will only add records to the authority and additional data sections when they are required. | boolean |
| infoblox_bloxone_ddi.dns_config.name | Name of view. | keyword |
| infoblox_bloxone_ddi.dns_config.notify | notify all external secondary DNS servers. | boolean |
| infoblox_bloxone_ddi.dns_config.query_acl.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.query_acl.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.query_acl.value | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.recursion_acl.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_acl.value | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.recursion_enabled | Optional. true to allow recursive DNS queries. | boolean |
| infoblox_bloxone_ddi.dns_config.synthesize.address_records_from_https | synthesize_address_records_from_https enables/disables creation of A/AAAA records from HTTPS RR. | boolean |
| infoblox_bloxone_ddi.dns_config.tags | Tagging specifics. | flattened |
| infoblox_bloxone_ddi.dns_config.transfer_acl.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.transfer_acl.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.transfer_acl.value | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.access | Access permission for element. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.address | Optional. Data for ip element. | ip |
| infoblox_bloxone_ddi.dns_config.update_acl.element | Type of element. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.tsig_key.algorithm | TSIG key algorithm. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.tsig_key.comment | Comment for TSIG key. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.tsig_key.key | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.tsig_key.name | TSIG key name, FQDN. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.tsig_key.protocol.name | TSIG key name in punycode. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.tsig_key.secret | TSIG key secret, base64 string. | keyword |
| infoblox_bloxone_ddi.dns_config.update_acl.value | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_config.updated_at | The timestamp when the object has been updated. Equals to created_at if not updated after creation. | date |
| infoblox_bloxone_ddi.dns_config.use_forwarders_for_subzones | Optional. Use default forwarders to resolve queries for subzones. | boolean |
| infoblox_bloxone_ddi.dns_config.zone_authority.default_ttl | Optional. ZoneAuthority default ttl for resource records in zone (value in seconds). | long |
| infoblox_bloxone_ddi.dns_config.zone_authority.expire | Optional. ZoneAuthority expire time in seconds. Defaults to 2419200. | long |
| infoblox_bloxone_ddi.dns_config.zone_authority.mname | Optional. ZoneAuthority master name server (partially qualified domain name) Defaults to empty. | keyword |
| infoblox_bloxone_ddi.dns_config.zone_authority.negative_ttl | Optional. ZoneAuthority negative caching (minimum) ttl in seconds. | long |
| infoblox_bloxone_ddi.dns_config.zone_authority.protocol.mname | Optional. ZoneAuthority master name server in punycode. Defaults to empty. | keyword |
| infoblox_bloxone_ddi.dns_config.zone_authority.protocol.rname | Optional. A domain name which specifies the mailbox of the person responsible for this zone. Defaults to empty. | keyword |
| infoblox_bloxone_ddi.dns_config.zone_authority.refresh | Optional. ZoneAuthority refresh. Defaults to 10800. | long |
| infoblox_bloxone_ddi.dns_config.zone_authority.retry | Optional. ZoneAuthority retry. Defaults to 3600. | long |
| infoblox_bloxone_ddi.dns_config.zone_authority.rname | Optional. ZoneAuthority rname. Defaults to empty. | keyword |
| infoblox_bloxone_ddi.dns_config.zone_authority.use_default_mname | Optional. Use default value for master name server. Defaults to true. | boolean |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### dns_data

This is the `dns_data` dataset.

#### Example

An example event for `dns_data` looks as following:

```json
{
    "@timestamp": "2022-07-20T09:59:59.184Z",
    "agent": {
        "ephemeral_id": "47fb54e0-4eeb-4563-b51b-3c6fbb0d8a64",
        "hostname": "docker-fleet-agent",
        "id": "e0bb9c9c-c3ad-47d7-882c-5fff0f458160",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "infoblox_bloxone_ddi.dns_data",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "answers": {
            "ttl": 0
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e0bb9c9c-c3ad-47d7-882c-5fff0f458160",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2022-07-20T09:59:59.184Z",
        "dataset": "infoblox_bloxone_ddi.dns_data",
        "id": "ghr123ghf",
        "ingested": "2022-11-21T10:36:50Z",
        "kind": "event",
        "original": "{\"absolute_name_spec\":\"DNS Data Absolute Name\",\"absolute_zone_name\":\"DNS Data Absolute Zone Name\",\"comment\":\"DNS Data Comment\",\"created_at\":\"2022-07-20T09:59:59.184Z\",\"delegation\":\"DNS Data Delegation\",\"disabled\":true,\"dns_absolute_name_spec\":\"DNS Absolute Name\",\"dns_absolute_zone_name\":\"DNS Absolute Zone Name\",\"dns_name_in_zone\":\"DNS Name in Zone\",\"dns_rdata\":\"DNS RData\",\"id\":\"ghr123ghf\",\"inheritance_sources\":{\"ttl\":{\"action\":\"DNS Data Action\",\"display_name\":\"DNS Display Name\",\"source\":\"DNS Data Source\",\"value\":10}},\"name_in_zone\":\"DNS Data Name in zone\",\"options\":{\"address\":\"67.43.156.0\",\"check_rmz\":true,\"create_ptr\":false},\"rdata\":{\"address\":\"81.2.69.192\",\"cname\":\"DNS Data Canonical Name\",\"dhcid\":\"122zbczba12\",\"dname\":\"DNS Data dname\",\"exchange\":\"DNS Data Exchange\",\"expire\":23131,\"flags\":\"DNS Data Flags\",\"length_kind\":8,\"mname\":\"DNS Data mname\",\"negative_ttl\":213342,\"order\":123124,\"port\":80,\"preference\":12345363467,\"priority\":44,\"refresh\":10800,\"regexp\":\"none\",\"replacement\":\"DNS Data Replacement\",\"retry\":3600,\"rname\":\"DNS Data rname\",\"serial\":12314114,\"services\":\"DNS Data Test Services\",\"tag\":\"issue\",\"target\":\"DNS Data Target\",\"text\":\"DNS Data text field\",\"type\":\"32BIT\",\"value\":\"DNS Data Value\",\"weight\":0},\"source\":[\"STATIC\"],\"tags\":{\"message\":\"Hello\"},\"ttl\":0,\"type\":\"DNS Data Type\",\"updated_at\":\"2022-07-20T09:59:59.184Z\",\"view\":\"DNS Data View\",\"view_name\":\"DNS Data View Name\",\"zone\":\"DNS Data Zone\"}",
        "type": [
            "protocol"
        ]
    },
    "infoblox_bloxone_ddi": {
        "dns_data": {
            "absolute": {
                "name": {
                    "spec": "DNS Absolute Name"
                },
                "zone": {
                    "name": "DNS Absolute Zone Name"
                }
            },
            "absolute_name": {
                "spec": "DNS Data Absolute Name"
            },
            "absolute_zone": {
                "name": "DNS Data Absolute Zone Name"
            },
            "comment": "DNS Data Comment",
            "created_at": "2022-07-20T09:59:59.184Z",
            "delegation": "DNS Data Delegation",
            "disabled": true,
            "id": "ghr123ghf",
            "inheritance": {
                "sources": {
                    "ttl": {
                        "action": "DNS Data Action",
                        "display": {
                            "name": "DNS Display Name"
                        },
                        "source": "DNS Data Source",
                        "value": 10
                    }
                }
            },
            "name_in": {
                "zone": "DNS Name in Zone"
            },
            "name_in_zone": "DNS Data Name in zone",
            "options": {
                "address": "67.43.156.0",
                "check_rmz": true,
                "create_ptr": false
            },
            "rdata": {
                "address": "81.2.69.192",
                "cname": "DNS Data Canonical Name",
                "dhcid": "122zbczba12",
                "dname": "DNS Data dname",
                "exchange": "DNS Data Exchange",
                "expire": 23131,
                "flags": "DNS Data Flags",
                "length_kind": 8,
                "mname": "DNS Data mname",
                "negative_ttl": 213342,
                "order": 123124,
                "port": 80,
                "preference": 12345363467,
                "priority": 44,
                "refresh": 10800,
                "regexp": "none",
                "replacement": "DNS Data Replacement",
                "retry": 3600,
                "rname": "DNS Data rname",
                "serial": 12314114,
                "services": "DNS Data Test Services",
                "tag": "issue",
                "target": "DNS Data Target",
                "text": "DNS Data text field",
                "type": "32BIT",
                "value": "DNS Data Value",
                "weight": 0
            },
            "rdata_value": "DNS RData",
            "source": [
                "STATIC"
            ],
            "tags": {
                "message": "Hello"
            },
            "ttl": 0,
            "type": "DNS Data Type",
            "updated_at": "2022-07-20T09:59:59.184Z",
            "view": "DNS Data View",
            "view_name": "DNS Data View Name",
            "zone": "DNS Data Zone"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "67.43.156.0",
            "81.2.69.192"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "bloxone_ddi-dns_data"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| infoblox_bloxone_ddi.dns_data.absolute.name.spec | The DNS protocol textual representation of absolute_name_spec. | keyword |
| infoblox_bloxone_ddi.dns_data.absolute.zone.name | The DNS protocol textual representation of the absolute domain name of the zone where this record belongs. | keyword |
| infoblox_bloxone_ddi.dns_data.absolute_name.spec | Synthetic field, used to determine zone and/or name_in_zone field for records. | keyword |
| infoblox_bloxone_ddi.dns_data.absolute_zone.name | The absolute domain name of the zone where this record belongs. | keyword |
| infoblox_bloxone_ddi.dns_data.comment | The description for the DNS resource record. May contain 0 to 1024 characters. Can include UTF-8. | keyword |
| infoblox_bloxone_ddi.dns_data.created_at | The timestamp when the object has been created. | date |
| infoblox_bloxone_ddi.dns_data.delegation | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_data.disabled | Indicates if the DNS resource record is disabled. A disabled object is effectively non-existent when generating configuration. | boolean |
| infoblox_bloxone_ddi.dns_data.id | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_data.inheritance.sources.ttl.action | The inheritance setting for a field. | keyword |
| infoblox_bloxone_ddi.dns_data.inheritance.sources.ttl.display.name | The human-readable display name for the object referred to by source. | keyword |
| infoblox_bloxone_ddi.dns_data.inheritance.sources.ttl.source | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_data.inheritance.sources.ttl.value | The inherited value. | long |
| infoblox_bloxone_ddi.dns_data.name_in.zone | The DNS protocol textual representation of the relative owner name for the DNS zone. | keyword |
| infoblox_bloxone_ddi.dns_data.name_in_zone | The relative owner name to the zone origin. Must be specified for creating the DNS resource record and is read only for other operations. | keyword |
| infoblox_bloxone_ddi.dns_data.options.address | For GET operation it contains the IPv4 or IPv6 address represented by the PTR record and for POST and PATCH operations it can be used to create/update a PTR record based on the IP address it represents. In this case, in addition to the address in the options field, need to specify the view field. | ip |
| infoblox_bloxone_ddi.dns_data.options.check_rmz | A boolean flag which can be set to true for POST operation to check the existence of reverse zone for creating the corresponding PTR record. Only applicable if the create_ptr option is set to true. | boolean |
| infoblox_bloxone_ddi.dns_data.options.create_ptr | A boolean flag which can be set to true for POST operation to automatically create the corresponding PTR record. | boolean |
| infoblox_bloxone_ddi.dns_data.provider_metadata | external DNS provider metadata. | flattened |
| infoblox_bloxone_ddi.dns_data.rdata.address | The IPv4/IPv6 address of the host. | ip |
| infoblox_bloxone_ddi.dns_data.rdata.cname | A domain name which specifies the canonical or primary name for the owner. The owner name is an alias. Can be empty. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.dhcid | The Base64 encoded string which contains DHCP client information. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.dname | A domain-name which specifies a host which should be authoritative for the specified class and domain. Can be absolute or relative domain name and include UTF-8. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.exchange | A domain name which specifies a host willing to act as a mail exchange for the owner name. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.expire | The time interval in seconds after which zone data will expire and secondary server stops answering requests for the zone. | long |
| infoblox_bloxone_ddi.dns_data.rdata.flags | An unsigned 8-bit integer which specifies the CAA record flags. RFC 6844 defines one (highest) bit in flag octet, remaining bits are deferred for future use. This bit is referenced as Critical. When the bit is set (flag value == 128), issuers must not issue certificates in case CAA records contain unknown property tags. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.length_kind | A string indicating the size in bits of a sub-subfield that is prepended to the value and encodes the length of the value. | long |
| infoblox_bloxone_ddi.dns_data.rdata.mname | The domain name for the master server for the zone. Can be absolute or relative domain name. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.negative_ttl | The time interval in seconds for which name servers can cache negative responses for zone. | long |
| infoblox_bloxone_ddi.dns_data.rdata.order | A 16-bit unsigned integer specifying the order in which the NAPTR records must be processed. Low numbers are processed before high numbers, and once a NAPTR is found whose rule “matches” the target, the client must not consider any NAPTRs with a higher value for order (except as noted below for the “flags” field. The range of the value is 0 to 65535. | long |
| infoblox_bloxone_ddi.dns_data.rdata.port | An unsigned 16-bit integer which specifies the port on this target host of this service. The range of the value is 0 to 65535. This is often as specified in Assigned Numbers but need not be. | long |
| infoblox_bloxone_ddi.dns_data.rdata.preference | An unsigned 16-bit integer which specifies the preference given to this RR among others at the same owner. Lower values are preferred. The range of the value is 0 to 65535. | long |
| infoblox_bloxone_ddi.dns_data.rdata.priority | An unsigned 16-bit integer which specifies the priority of this target host. The range of the value is 0 to 65535. A client must attempt to contact the target host with the lowest-numbered priority it can reach. Target hosts with the same priority should be tried in an order defined by the weight field. | long |
| infoblox_bloxone_ddi.dns_data.rdata.refresh | The time interval in seconds that specifies how often secondary servers need to send a message to the primary server for a zone to check that their data is current, and retrieve fresh data if it is not. | long |
| infoblox_bloxone_ddi.dns_data.rdata.regexp | A string containing a substitution expression that is applied to the original string held by the client in order to construct the next domain name to lookup. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.replacement | The next name to query for NAPTR, SRV, or address records depending on the value of the flags field. This can be an absolute or relative domain name. Can be empty. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.retry | The time interval in seconds for which the secondary server will wait before attempting to recontact the primary server after a connection failure occurs. | long |
| infoblox_bloxone_ddi.dns_data.rdata.rname | The domain name which specifies the mailbox of the person responsible for this zone. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.serial | An unsigned 32-bit integer that specifies the serial number of the zone. Used to indicate that zone data was updated, so the secondary name server can initiate zone transfer. The range of the value is 0 to 4294967295. | long |
| infoblox_bloxone_ddi.dns_data.rdata.services | Specifies the service(s) available down this rewrite path. It may also specify the particular protocol that is used to talk with a service. A protocol must be specified if the flags field states that the NAPTR is terminal. If a protocol is specified, but the flags field does not state that the NAPTR is terminal, the next lookup must be for a NAPTR. The client may choose not to perform the next lookup if the protocol is unknown, but that behavior must not be relied upon. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.tag | The CAA record property tag string which indicates the type of CAA record. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.target | The target domain name to which the zone will be mapped. Can be empty. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.text | The semantics of the text depends on the domain where it is found. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.type | Type of TXT (Text) record. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.value | A string which contains the CAA record property value. | keyword |
| infoblox_bloxone_ddi.dns_data.rdata.weight | An unsigned 16-bit integer which specifies a relative weight for entries with the same priority. The range of the value is 0 to 65535. Larger weights should be given a proportionately higher probability of being selected. Domain administrators should use weight 0 when there isn’t any server selection to do, to make the RR easier to read for humans (less noisy). In the presence of records containing weights greater than 0, records with weight 0 should have a very small chance of being selected. | long |
| infoblox_bloxone_ddi.dns_data.rdata_value | The DNS protocol textual representation of the DNS resource record data. | keyword |
| infoblox_bloxone_ddi.dns_data.source | The DNS resource record type-specific non-protocol source. The source is a combination of indicators, each tracking how the DNS resource record appeared in system. | keyword |
| infoblox_bloxone_ddi.dns_data.tags | The tags for the DNS resource record in JSON format. | flattened |
| infoblox_bloxone_ddi.dns_data.ttl | The record time to live value in seconds. The range of this value is 0 to 2147483647. Defaults to TTL value from the SOA record of the zone. | long |
| infoblox_bloxone_ddi.dns_data.type | The DNS resource record type specified in the textual mnemonic format or in the “TYPEnnn” format where “nnn” indicates the numeric type value. | keyword |
| infoblox_bloxone_ddi.dns_data.updated_at | The timestamp when the object has been updated. Equals to created_at if not updated after creation. | date |
| infoblox_bloxone_ddi.dns_data.view | The resource identifier. | keyword |
| infoblox_bloxone_ddi.dns_data.view_name | The display name of the DNS view that contains the parent zone of the DNS resource record. | keyword |
| infoblox_bloxone_ddi.dns_data.zone | The resource identifier. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |

