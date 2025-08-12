# NetBox Integration

This integration is for [NetBox](). It currently supports retrieving devices and ip addresses from the NetBox API.

## Setup

Retrieve an [API token](https://netboxlabs.com/docs/netbox/integrations/rest-api/#initial-token-provisioning) from your NetBox Server and update the URL to your NetBox Server.

## Compatibility

The NetBox module has been developed with and tested against the [community edition](https://github.com/netbox-community/netbox) version 4.3.5

## Logs

### Devices

Collects devices from the [Devices API](https://demo.netbox.dev/api/schema/swagger-ui/#/dcim/dcim_devices_list).

An example event for `devices` looks as following:

```json
{
    "@timestamp": "2025-08-12T14:06:39.058Z",
    "agent": {
        "ephemeral_id": "13f5e395-3fd9-4dd3-beea-df5ffdfa2f37",
        "id": "15bfbadd-b33f-4a0a-b07c-f06f935fc69e",
        "name": "elastic-agent-20709",
        "type": "filebeat",
        "version": "9.1.0"
    },
    "data_stream": {
        "dataset": "netbox.devices",
        "namespace": "38366",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "15bfbadd-b33f-4a0a-b07c-f06f935fc69e",
        "snapshot": false,
        "version": "9.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "created": "2025-08-12T14:06:39.058Z",
        "dataset": "netbox.devices",
        "ingested": "2025-08-12T14:06:42Z",
        "kind": "event",
        "original": "{\"airflow\":{\"label\":\"Front to rear\",\"value\":\"front-to-rear\"},\"asset_tag\":\"WEB-001\",\"cluster\":{\"description\":\"Production web application cluster\",\"display\":\"web-cluster\",\"id\":1,\"name\":\"web-cluster\",\"url\":\"http://localhost:8000/api/virtualization/clusters/1/\"},\"comments\":\"\",\"config_context\":{\"backup_enabled\":true,\"environment\":\"production\"},\"config_template\":{\"description\":\"Standard Ubuntu web server configuration template\",\"display\":\"ubuntu-web-template\",\"id\":1,\"name\":\"ubuntu-web-template\",\"url\":\"http://localhost:8000/api/extras/config-templates/1/\"},\"console_port_count\":0,\"console_server_port_count\":0,\"created\":\"2025-08-11T14:37:28.180540Z\",\"custom_fields\":{\"maintenance_window\":\"Sunday 02:00-04:00 EST\"},\"description\":\"Primary web server for customer portal\",\"device_bay_count\":0,\"device_type\":{\"description\":\"Dell PowerEdge R740 2U Rack Server\",\"display\":\"dell poweredge r740\",\"id\":1,\"manufacturer\":{\"description\":\"\",\"display\":\"Dell\",\"id\":1,\"name\":\"Dell\",\"slug\":\"dell\",\"url\":\"http://localhost:8000/api/dcim/manufacturers/1/\"},\"model\":\"poweredge r740\",\"slug\":\"poweredge-r740\",\"url\":\"http://localhost:8000/api/dcim/device-types/1/\"},\"display\":\"web-srv-01 (WEB-001)\",\"display_url\":\"http://localhost:8000/dcim/devices/2/\",\"face\":{\"label\":\"Front\",\"value\":\"front\"},\"front_port_count\":0,\"id\":2,\"interface_count\":4,\"inventory_item_count\":0,\"last_updated\":\"2025-08-11T18:12:23.512163Z\",\"latitude\":39.0458,\"local_context_data\":{\"monitoring\":\"enabled\",\"ssl_cert\":\"wildcard.acme.com\"},\"location\":{\"_depth\":0,\"description\":\"Primary server room - Zone A\",\"display\":\"server-room-a\",\"id\":1,\"name\":\"server-room-a\",\"rack_count\":0,\"slug\":\"server-room-a\",\"url\":\"http://localhost:8000/api/dcim/locations/1/\"},\"longitude\":-76.6413,\"module_bay_count\":0,\"name\":\"web-srv-01\",\"oob_ip\":{\"address\":\"10.0.100.15/24\",\"description\":\"Out-of-band management interface\",\"display\":\"10.0.100.15/24\",\"family\":{\"label\":\"IPv4\",\"value\":4},\"id\":1,\"url\":\"http://localhost:8000/api/ipam/ip-addresses/1/\"},\"parent_device\":null,\"platform\":{\"description\":\"Ubuntu Server 22.04 LTS\",\"display\":\"ubuntu-server\",\"id\":1,\"name\":\"ubuntu-server\",\"slug\":\"ubuntu-server\",\"url\":\"http://localhost:8000/api/dcim/platforms/1/\"},\"position\":15,\"power_outlet_count\":0,\"power_port_count\":2,\"primary_ip\":{\"address\":\"10.0.1.15/24\",\"description\":\"Primary web server interface\",\"display\":\"10.0.1.15/24\",\"family\":{\"label\":\"IPv4\",\"value\":4},\"id\":1,\"url\":\"http://localhost:8000/api/ipam/ip-addresses/1/\"},\"primary_ip4\":{\"address\":\"10.0.1.15/24\",\"description\":\"Primary web server interface\",\"display\":\"10.0.1.15/24\",\"family\":{\"label\":\"IPv4\",\"value\":4},\"id\":1,\"url\":\"http://localhost:8000/api/ipam/ip-addresses/1/\"},\"primary_ip6\":null,\"rack\":{\"description\":\"42U server rack - Zone A, Row 1\",\"display\":\"rack-a01 (DC-EAST-A01)\",\"id\":1,\"name\":\"rack-a01\",\"url\":\"http://localhost:8000/api/dcim/racks/1/\"},\"rear_port_count\":0,\"role\":{\"_depth\":0,\"description\":\"\",\"display\":\"web-server\",\"id\":1,\"name\":\"web-server\",\"slug\":\"web-server\",\"url\":\"http://localhost:8000/api/dcim/device-roles/1/\"},\"serial\":\"CN7016A2B90001\",\"site\":{\"description\":\"\",\"display\":\"datacenter-east\",\"id\":1,\"name\":\"datacenter-east\",\"slug\":\"datacenter-east\",\"url\":\"http://localhost:8000/api/dcim/sites/1/\"},\"status\":{\"label\":\"Active\",\"value\":\"active\"},\"tags\":[{\"color\":\"4caf50\",\"display\":\"production\",\"display_url\":\"http://localhost:8000/extras/tags/2/\",\"id\":2,\"name\":\"production\",\"slug\":\"production\",\"url\":\"http://localhost:8000/api/extras/tags/2/\"},{\"color\":\"2196f3\",\"display\":\"web-tier\",\"display_url\":\"http://localhost:8000/extras/tags/4/\",\"id\":4,\"name\":\"web-tier\",\"slug\":\"web-tier\",\"url\":\"http://localhost:8000/api/extras/tags/4/\"},{\"color\":\"f44336\",\"display\":\"critical\",\"display_url\":\"http://localhost:8000/extras/tags/1/\",\"id\":1,\"name\":\"critical\",\"slug\":\"critical\",\"url\":\"http://localhost:8000/api/extras/tags/1/\"},{\"color\":\"ff9800\",\"display\":\"monitored\",\"display_url\":\"http://localhost:8000/extras/tags/3/\",\"id\":3,\"name\":\"monitored\",\"slug\":\"monitored\",\"url\":\"http://localhost:8000/api/extras/tags/3/\"}],\"tenant\":{\"description\":\"Acme Corporation primary tenant\",\"display\":\"acme-corp\",\"id\":1,\"name\":\"acme-corp\",\"slug\":\"acme-corp\",\"url\":\"http://localhost:8000/api/tenancy/tenants/1/\"},\"url\":\"http://localhost:8000/api/dcim/devices/2/\",\"vc_position\":1,\"vc_priority\":null,\"virtual_chassis\":{\"description\":\"\",\"display\":\"web-cluster-vc\",\"id\":1,\"master\":{\"display\":\"web-srv-01 (WEB-001)\",\"display_url\":\"http://localhost:8000/dcim/devices/2/\",\"id\":2,\"name\":\"web-srv-01\",\"url\":\"http://localhost:8000/api/dcim/devices/2/\"},\"member_count\":2,\"name\":\"web-cluster-vc\",\"url\":\"http://localhost:8000/api/dcim/virtual-chassis/1/\"}}"
    },
    "input": {
        "type": "httpjson"
    },
    "netbox": {
        "device": {
            "airflow": {
                "label": "Front to rear",
                "value": "front-to-rear"
            },
            "asset_tag": "WEB-001",
            "cluster": {
                "description": "Production web application cluster",
                "display": "web-cluster",
                "id": 1,
                "name": "web-cluster",
                "url": "http://localhost:8000/api/virtualization/clusters/1/"
            },
            "config_context": {
                "backup_enabled": "true",
                "environment": "production"
            },
            "config_template": {
                "description": "Standard Ubuntu web server configuration template",
                "display": "ubuntu-web-template",
                "id": 1,
                "name": "ubuntu-web-template",
                "url": "http://localhost:8000/api/extras/config-templates/1/"
            },
            "console_port_count": 0,
            "console_server_port_count": 0,
            "created": "2025-08-11T14:37:28.180Z",
            "custom_fields": {
                "maintenance_window": "Sunday 02:00-04:00 EST"
            },
            "description": "Primary web server for customer portal",
            "device_bay_count": 0,
            "device_type": {
                "description": "Dell PowerEdge R740 2U Rack Server",
                "display": "dell poweredge r740",
                "id": 1,
                "manufacturer": {
                    "display": "Dell",
                    "id": 1,
                    "name": "Dell",
                    "slug": "dell",
                    "url": "http://localhost:8000/api/dcim/manufacturers/1/"
                },
                "model": "poweredge r740",
                "slug": "poweredge-r740",
                "url": "http://localhost:8000/api/dcim/device-types/1/"
            },
            "display": "web-srv-01 (WEB-001)",
            "display_url": "http://localhost:8000/dcim/devices/2/",
            "face": {
                "label": "Front",
                "value": "front"
            },
            "front_port_count": 0,
            "id": 2,
            "interface_count": 4,
            "inventory_item_count": 0,
            "last_updated": "2025-08-11T18:12:23.512Z",
            "latitude": 39.0458,
            "local_context_data": {
                "monitoring": "enabled",
                "ssl_cert": "wildcard.acme.com"
            },
            "location": {
                "_depth": 0,
                "description": "Primary server room - Zone A",
                "display": "server-room-a",
                "id": 1,
                "name": "server-room-a",
                "rack_count": 0,
                "slug": "server-room-a",
                "url": "http://localhost:8000/api/dcim/locations/1/"
            },
            "longitude": -76.6413,
            "module_bay_count": 0,
            "name": "web-srv-01",
            "oob_ip": {
                "address": "10.0.100.15",
                "description": "Out-of-band management interface",
                "display": "10.0.100.15/24",
                "family": {
                    "label": "IPv4",
                    "value": 4
                },
                "id": 1,
                "url": "http://localhost:8000/api/ipam/ip-addresses/1/"
            },
            "platform": {
                "description": "Ubuntu Server 22.04 LTS",
                "display": "ubuntu-server",
                "id": 1,
                "name": "ubuntu-server",
                "slug": "ubuntu-server",
                "url": "http://localhost:8000/api/dcim/platforms/1/"
            },
            "position": 15,
            "power_outlet_count": 0,
            "power_port_count": 2,
            "primary_ip": {
                "address": "10.0.1.15",
                "description": "Primary web server interface",
                "display": "10.0.1.15/24",
                "family": {
                    "label": "IPv4",
                    "value": 4
                },
                "id": 1,
                "url": "http://localhost:8000/api/ipam/ip-addresses/1/"
            },
            "primary_ip4": {
                "address": "10.0.1.15",
                "description": "Primary web server interface",
                "display": "10.0.1.15/24",
                "family": {
                    "label": "IPv4",
                    "value": 4
                },
                "id": 1,
                "url": "http://localhost:8000/api/ipam/ip-addresses/1/"
            },
            "rack": {
                "description": "42U server rack - Zone A, Row 1",
                "display": "rack-a01 (DC-EAST-A01)",
                "id": 1,
                "name": "rack-a01",
                "url": "http://localhost:8000/api/dcim/racks/1/"
            },
            "rear_port_count": 0,
            "role": {
                "_depth": 0,
                "display": "web-server",
                "id": 1,
                "name": "web-server",
                "slug": "web-server",
                "url": "http://localhost:8000/api/dcim/device-roles/1/"
            },
            "serial": "CN7016A2B90001",
            "site": {
                "display": "datacenter-east",
                "id": 1,
                "name": "datacenter-east",
                "slug": "datacenter-east",
                "url": "http://localhost:8000/api/dcim/sites/1/"
            },
            "status": {
                "label": "Active",
                "value": "active"
            },
            "tags": [
                {
                    "color": [
                        "4caf50"
                    ],
                    "display": [
                        "production"
                    ],
                    "display_url": [
                        "http://localhost:8000/extras/tags/2/"
                    ],
                    "id": [
                        2
                    ],
                    "name": [
                        "production"
                    ],
                    "slug": [
                        "production"
                    ],
                    "url": [
                        "http://localhost:8000/api/extras/tags/2/"
                    ]
                },
                {
                    "color": [
                        "2196f3"
                    ],
                    "display": [
                        "web-tier"
                    ],
                    "display_url": [
                        "http://localhost:8000/extras/tags/4/"
                    ],
                    "id": [
                        4
                    ],
                    "name": [
                        "web-tier"
                    ],
                    "slug": [
                        "web-tier"
                    ],
                    "url": [
                        "http://localhost:8000/api/extras/tags/4/"
                    ]
                },
                {
                    "color": [
                        "f44336"
                    ],
                    "display": [
                        "critical"
                    ],
                    "display_url": [
                        "http://localhost:8000/extras/tags/1/"
                    ],
                    "id": [
                        1
                    ],
                    "name": [
                        "critical"
                    ],
                    "slug": [
                        "critical"
                    ],
                    "url": [
                        "http://localhost:8000/api/extras/tags/1/"
                    ]
                },
                {
                    "color": [
                        "ff9800"
                    ],
                    "display": [
                        "monitored"
                    ],
                    "display_url": [
                        "http://localhost:8000/extras/tags/3/"
                    ],
                    "id": [
                        3
                    ],
                    "name": [
                        "monitored"
                    ],
                    "slug": [
                        "monitored"
                    ],
                    "url": [
                        "http://localhost:8000/api/extras/tags/3/"
                    ]
                }
            ],
            "tenant": {
                "description": "Acme Corporation primary tenant",
                "display": "acme-corp",
                "id": 1,
                "name": "acme-corp",
                "slug": "acme-corp",
                "url": "http://localhost:8000/api/tenancy/tenants/1/"
            },
            "url": "http://localhost:8000/api/dcim/devices/2/",
            "vc_position": 1,
            "virtual_chassis": {
                "display": "web-cluster-vc",
                "id": 1,
                "master": {
                    "display": "web-srv-01 (WEB-001)",
                    "display_url": "http://localhost:8000/dcim/devices/2/",
                    "id": 2,
                    "name": "web-srv-01",
                    "url": "http://localhost:8000/api/dcim/devices/2/"
                },
                "member_count": 2,
                "name": "web-cluster-vc",
                "url": "http://localhost:8000/api/dcim/virtual-chassis/1/"
            }
        }
    },
    "related": {
        "ip": [
            "10.0.1.15",
            "10.0.100.15"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "netbox-devices"
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
| input.type | Input type | keyword |
| netbox.device.airflow.label | The airflow label of the device. | keyword |
| netbox.device.airflow.value | The airflow value of the device. | keyword |
| netbox.device.asset_tag | The asset tag of the device. | keyword |
| netbox.device.cluster.description |  | text |
| netbox.device.cluster.display |  | keyword |
| netbox.device.cluster.id |  | long |
| netbox.device.cluster.name |  | keyword |
| netbox.device.cluster.url |  | keyword |
| netbox.device.comments | Comments about the device. | text |
| netbox.device.config_context | The configuration context of the device. | object |
| netbox.device.config_template.description |  | text |
| netbox.device.config_template.display |  | keyword |
| netbox.device.config_template.id |  | long |
| netbox.device.config_template.name |  | keyword |
| netbox.device.config_template.url |  | keyword |
| netbox.device.console_port_count | The number of console ports on the device. | long |
| netbox.device.console_server_port_count | The number of console server ports on the device. | long |
| netbox.device.created | The creation timestamp of the device record. | date |
| netbox.device.custom_fields | Custom fields associated with the device. | object |
| netbox.device.description | The description of the device. | text |
| netbox.device.device_bay_count | The number of device bays on the device. | long |
| netbox.device.device_type.description | The description of the device type. | text |
| netbox.device.device_type.display | The display name of the device type. | keyword |
| netbox.device.device_type.id | The unique identifier of the device type. | long |
| netbox.device.device_type.manufacturer.description | The description of the manufacturer. | text |
| netbox.device.device_type.manufacturer.display | The display name of the manufacturer. | keyword |
| netbox.device.device_type.manufacturer.id | The unique identifier of the manufacturer. | long |
| netbox.device.device_type.manufacturer.name | The name of the manufacturer. | keyword |
| netbox.device.device_type.manufacturer.slug | The slug of the manufacturer. | keyword |
| netbox.device.device_type.manufacturer.url | The API URL for the manufacturer. | keyword |
| netbox.device.device_type.model | The model of the device type. | keyword |
| netbox.device.device_type.slug | The slug of the device type. | keyword |
| netbox.device.device_type.url | The API URL for the device type. | keyword |
| netbox.device.display | The display name of the device. | keyword |
| netbox.device.display_url | The display URL for the device. | keyword |
| netbox.device.face.label | The label of the device face. | keyword |
| netbox.device.face.value | The value of the device face. | keyword |
| netbox.device.front_port_count | The number of front ports on the device. | long |
| netbox.device.id | The unique identifier of the device. | long |
| netbox.device.interface_count | The number of interfaces on the device. | long |
| netbox.device.inventory_item_count | The number of inventory items associated with the device. | long |
| netbox.device.last_updated | The last update timestamp of the device record. | date |
| netbox.device.latitude | The latitude coordinate of the device. | double |
| netbox.device.local_context_data | The local context data of the device. | object |
| netbox.device.location._depth | The depth level of the location. | long |
| netbox.device.location.description | The description of the location. | text |
| netbox.device.location.display | The display name of the location. | keyword |
| netbox.device.location.id | The unique identifier of the location. | long |
| netbox.device.location.name | The name of the location. | keyword |
| netbox.device.location.rack_count | The number of racks in the location. | long |
| netbox.device.location.slug | The slug of the location. | keyword |
| netbox.device.location.url | The API URL for the location. | keyword |
| netbox.device.longitude | The longitude coordinate of the device. | double |
| netbox.device.module_bay_count | The number of module bays on the device. | long |
| netbox.device.name | The name of the device. | keyword |
| netbox.device.oob_ip.address |  | ip |
| netbox.device.oob_ip.description |  | text |
| netbox.device.oob_ip.display |  | keyword |
| netbox.device.oob_ip.family.label |  | keyword |
| netbox.device.oob_ip.family.value |  | long |
| netbox.device.oob_ip.id |  | long |
| netbox.device.oob_ip.name |  | keyword |
| netbox.device.oob_ip.url |  | keyword |
| netbox.device.parent_device | The parent device identifier. | keyword |
| netbox.device.platform.description | The description of the platform. | text |
| netbox.device.platform.display | The display name of the platform. | keyword |
| netbox.device.platform.id | The unique identifier of the platform. | long |
| netbox.device.platform.name | The name of the platform. | keyword |
| netbox.device.platform.slug | The slug of the platform. | keyword |
| netbox.device.platform.url | The API URL for the platform. | keyword |
| netbox.device.position | The position of the device in the rack. | long |
| netbox.device.power_outlet_count | The number of power outlets on the device. | long |
| netbox.device.power_port_count | The number of power ports on the device. | long |
| netbox.device.primary_ip.address |  | ip |
| netbox.device.primary_ip.description |  | text |
| netbox.device.primary_ip.display |  | keyword |
| netbox.device.primary_ip.family.label |  | keyword |
| netbox.device.primary_ip.family.value |  | long |
| netbox.device.primary_ip.id |  | long |
| netbox.device.primary_ip.name |  | keyword |
| netbox.device.primary_ip.url |  | keyword |
| netbox.device.primary_ip4.address |  | ip |
| netbox.device.primary_ip4.description |  | text |
| netbox.device.primary_ip4.display |  | keyword |
| netbox.device.primary_ip4.family.label |  | keyword |
| netbox.device.primary_ip4.family.value |  | long |
| netbox.device.primary_ip4.id |  | long |
| netbox.device.primary_ip4.name |  | keyword |
| netbox.device.primary_ip4.url |  | keyword |
| netbox.device.primary_ip6.address |  | ip |
| netbox.device.primary_ip6.description |  | text |
| netbox.device.primary_ip6.display |  | keyword |
| netbox.device.primary_ip6.family.label |  | keyword |
| netbox.device.primary_ip6.family.value |  | long |
| netbox.device.primary_ip6.id |  | long |
| netbox.device.primary_ip6.name |  | keyword |
| netbox.device.primary_ip6.url |  | keyword |
| netbox.device.rack.description | The description of the rack. | text |
| netbox.device.rack.display | The display name of the rack. | keyword |
| netbox.device.rack.id | The unique identifier of the rack. | long |
| netbox.device.rack.name | The name of the rack. | keyword |
| netbox.device.rack.url | The API URL for the rack. | keyword |
| netbox.device.rear_port_count | The number of rear ports on the device. | long |
| netbox.device.role._depth | The depth level of the device role. | long |
| netbox.device.role.description | The description of the device role. | text |
| netbox.device.role.display | The display name of the device role. | keyword |
| netbox.device.role.id | The unique identifier of the device role. | long |
| netbox.device.role.name | The name of the device role. | keyword |
| netbox.device.role.slug | The slug of the device role. | keyword |
| netbox.device.role.url | The API URL for the device role. | keyword |
| netbox.device.serial | The serial number of the device. | keyword |
| netbox.device.site.description | The description of the site. | text |
| netbox.device.site.display | The display name of the site. | keyword |
| netbox.device.site.id | The unique identifier of the site. | long |
| netbox.device.site.name | The name of the site. | keyword |
| netbox.device.site.slug | The slug of the site. | keyword |
| netbox.device.site.url | The API URL for the site. | keyword |
| netbox.device.status.label | The status label of the device. | keyword |
| netbox.device.status.value | The status value of the device. | keyword |
| netbox.device.tags.color | The color code of the tag. | keyword |
| netbox.device.tags.display | The display name of the tag. | keyword |
| netbox.device.tags.display_url | The display URL for the tag. | keyword |
| netbox.device.tags.id | The unique identifier of the tag. | long |
| netbox.device.tags.name | The name of the tag. | keyword |
| netbox.device.tags.slug | The slug of the tag. | keyword |
| netbox.device.tags.url | The API URL for the tag. | keyword |
| netbox.device.tenant.description | The description of the tenant. | text |
| netbox.device.tenant.display | The display name of the tenant. | keyword |
| netbox.device.tenant.id | The unique identifier of the tenant. | long |
| netbox.device.tenant.name | The name of the tenant. | keyword |
| netbox.device.tenant.slug | The slug of the tenant. | keyword |
| netbox.device.tenant.url | The API URL for the tenant. | keyword |
| netbox.device.url | The API URL for the device. | keyword |
| netbox.device.vc_position | The virtual chassis position of the device. | long |
| netbox.device.vc_priority | The virtual chassis priority of the device. | long |
| netbox.device.virtual_chassis.description | The description of the virtual chassis. | text |
| netbox.device.virtual_chassis.display | The display name of the virtual chassis. | keyword |
| netbox.device.virtual_chassis.id | The unique identifier of the virtual chassis. | long |
| netbox.device.virtual_chassis.master.display |  | keyword |
| netbox.device.virtual_chassis.master.display_url |  | keyword |
| netbox.device.virtual_chassis.master.id |  | long |
| netbox.device.virtual_chassis.master.name |  | keyword |
| netbox.device.virtual_chassis.master.url |  | keyword |
| netbox.device.virtual_chassis.member_count |  | long |
| netbox.device.virtual_chassis.name | The name of the virtual chassis. | keyword |
| netbox.device.virtual_chassis.url | The API URL for the virtual chassis. | keyword |


### IPs

Collects IP addresses from the [IP Addresses API](https://demo.netbox.dev/api/schema/swagger-ui/#/ipam/ipam_ip_addresses_list).

An example event for `ips` looks as following:

```json
{
    "@timestamp": "2025-08-12T14:07:35.041Z",
    "agent": {
        "ephemeral_id": "ec908250-087e-45d1-936e-de1bf2ce87cd",
        "id": "205517fd-f37e-46c2-99d6-0a407ffeb4af",
        "name": "elastic-agent-28518",
        "type": "filebeat",
        "version": "9.1.0"
    },
    "data_stream": {
        "dataset": "netbox.ips",
        "namespace": "22331",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "205517fd-f37e-46c2-99d6-0a407ffeb4af",
        "snapshot": false,
        "version": "9.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "created": "2025-08-12T14:07:35.041Z",
        "dataset": "netbox.ips",
        "ingested": "2025-08-12T14:07:38Z",
        "kind": "event",
        "original": "{\"address\":\"192.168.1.101/32\",\"assigned_object\":{\"_occupied\":false,\"cable\":null,\"description\":\"test-description\",\"device\":{\"description\":\"test-description\",\"display\":\"user-1-macbook-pro (tag-1234)\",\"id\":1,\"name\":\"user-1-macbook-pro\",\"url\":\"http://localhost:8000/api/dcim/devices/1/\"},\"display\":\"hello\",\"id\":2,\"name\":\"user-hello\",\"url\":\"http://localhost:8000/api/dcim/interfaces/2/\"},\"assigned_object_id\":2,\"assigned_object_type\":\"dcim.interface\",\"comments\":\"\",\"created\":\"2025-08-11T18:07:04.795476Z\",\"custom_fields\":{},\"description\":\"desc\",\"display\":\"192.168.1.101/32\",\"display_url\":\"http://localhost:8000/ipam/ip-addresses/2/\",\"dns_name\":\"hello.world\",\"family\":{\"label\":\"IPv4\",\"value\":4},\"id\":2,\"last_updated\":\"2025-08-11T18:07:04.795486Z\",\"nat_inside\":null,\"nat_outside\":[],\"role\":{\"label\":\"Secondary\",\"value\":\"secondary\"},\"status\":{\"label\":\"Active\",\"value\":\"active\"},\"tags\":[{\"color\":\"ff9800\",\"display\":\"elastic\",\"display_url\":\"http://localhost:8000/extras/tags/4/\",\"id\":4,\"name\":\"elastic\",\"slug\":\"elastic\",\"url\":\"http://localhost:8000/api/extras/tags/4/\"}],\"tenant\":{\"description\":\"first tenant\",\"display\":\"tenant-1\",\"id\":1,\"name\":\"tenant-1\",\"slug\":\"tenant-1\",\"url\":\"http://localhost:8000/api/tenancy/tenants/1/\"},\"url\":\"http://localhost:8000/api/ipam/ip-addresses/2/\",\"vrf\":{\"description\":\"asdf\",\"display\":\"test\",\"id\":1,\"name\":\"test\",\"rd\":null,\"url\":\"http://localhost:8000/api/ipam/vrfs/1/\"}}"
    },
    "input": {
        "type": "httpjson"
    },
    "netbox": {
        "ip": {
            "address": "192.168.1.101",
            "assigned_object": {
                "_occupied": false,
                "description": "test-description",
                "device": {
                    "description": "test-description",
                    "display": "user-1-macbook-pro (tag-1234)",
                    "id": 1,
                    "name": "user-1-macbook-pro",
                    "url": "http://localhost:8000/api/dcim/devices/1/"
                },
                "display": "hello",
                "id": 2,
                "name": "user-hello",
                "url": "http://localhost:8000/api/dcim/interfaces/2/"
            },
            "assigned_object_id": 2,
            "assigned_object_type": "dcim.interface",
            "created": "2025-08-11T18:07:04.795Z",
            "description": "desc",
            "display": "192.168.1.101/32",
            "display_url": "http://localhost:8000/ipam/ip-addresses/2/",
            "dns_name": "hello.world",
            "family": {
                "label": "IPv4",
                "value": 4
            },
            "id": 2,
            "last_updated": "2025-08-11T18:07:04.795Z",
            "role": {
                "label": "Secondary",
                "value": "secondary"
            },
            "status": {
                "label": "Active",
                "value": "active"
            },
            "tags": {
                "color": [
                    "ff9800"
                ],
                "display": [
                    "elastic"
                ],
                "display_url": [
                    "http://localhost:8000/extras/tags/4/"
                ],
                "id": [
                    4
                ],
                "name": [
                    "elastic"
                ],
                "slug": [
                    "elastic"
                ],
                "url": [
                    "http://localhost:8000/api/extras/tags/4/"
                ]
            },
            "tenant": {
                "description": "first tenant",
                "display": "tenant-1",
                "id": 1,
                "name": "tenant-1",
                "slug": "tenant-1",
                "url": "http://localhost:8000/api/tenancy/tenants/1/"
            },
            "url": "http://localhost:8000/api/ipam/ip-addresses/2/",
            "vrf": {
                "description": "asdf",
                "display": "test",
                "id": 1,
                "name": "test",
                "url": "http://localhost:8000/api/ipam/vrfs/1/"
            }
        }
    },
    "related": {
        "ip": [
            "192.168.1.101"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "netbox-devices"
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
| input.type | Input type | keyword |
| netbox.ip.address |  | ip |
| netbox.ip.assigned_object._occupied | Whether the interface is occupied. | boolean |
| netbox.ip.assigned_object.cable | The cable connection information. | keyword |
| netbox.ip.assigned_object.description | The description of the assigned object. | text |
| netbox.ip.assigned_object.device.description | The description of the device. | text |
| netbox.ip.assigned_object.device.display | The display name of the device. | keyword |
| netbox.ip.assigned_object.device.id | The unique identifier of the device. | long |
| netbox.ip.assigned_object.device.name | The name of the device. | keyword |
| netbox.ip.assigned_object.device.url | The API URL for the device. | keyword |
| netbox.ip.assigned_object.display | The display name of the assigned object. | keyword |
| netbox.ip.assigned_object.id | The unique identifier of the assigned object. | long |
| netbox.ip.assigned_object.name | The name of the assigned object (interface). | keyword |
| netbox.ip.assigned_object.url | The API URL for the assigned object. | keyword |
| netbox.ip.assigned_object_id | The unique identifier of the assigned object. | long |
| netbox.ip.assigned_object_type | The type of object this IP address is assigned to. | keyword |
| netbox.ip.comments | Comments about the IP address. | text |
| netbox.ip.created | The creation timestamp of the IP address record. | date |
| netbox.ip.custom_fields | Custom fields associated with the IP address. | object |
| netbox.ip.description | The description of the IP address. | text |
| netbox.ip.display | The display representation of the IP address with CIDR notation. | keyword |
| netbox.ip.display_url | The display URL for the IP address. | keyword |
| netbox.ip.dns_name | The DNS name associated with the IP address. | keyword |
| netbox.ip.family.label | The IP family label (IPv4 or IPv6). | keyword |
| netbox.ip.family.value | The IP family value (4 for IPv4, 6 for IPv6). | long |
| netbox.ip.id | The unique identifier of the IP address. | long |
| netbox.ip.last_updated | The last update timestamp of the IP address record. | date |
| netbox.ip.nat_inside.address |  | ip |
| netbox.ip.nat_inside.display |  | keyword |
| netbox.ip.nat_inside.display_url |  | keyword |
| netbox.ip.nat_inside.family |  | long |
| netbox.ip.nat_inside.id |  | long |
| netbox.ip.nat_inside.url |  | keyword |
| netbox.ip.nat_outside.address |  | ip |
| netbox.ip.nat_outside.display |  | keyword |
| netbox.ip.nat_outside.display_url |  | keyword |
| netbox.ip.nat_outside.family |  | long |
| netbox.ip.nat_outside.id |  | long |
| netbox.ip.nat_outside.url |  | keyword |
| netbox.ip.role.label | The role label of the IP address. | keyword |
| netbox.ip.role.value | The role value of the IP address. | keyword |
| netbox.ip.status.label | The status label of the IP address. | keyword |
| netbox.ip.status.value | The status value of the IP address. | keyword |
| netbox.ip.tags.color | The color code of the tag. | keyword |
| netbox.ip.tags.display | The display name of the tag. | keyword |
| netbox.ip.tags.display_url | The display URL for the tag. | keyword |
| netbox.ip.tags.id | The unique identifier of the tag. | long |
| netbox.ip.tags.name | The name of the tag. | keyword |
| netbox.ip.tags.slug | The slug of the tag. | keyword |
| netbox.ip.tags.url | The API URL for the tag. | keyword |
| netbox.ip.tenant.description | The description of the tenant. | text |
| netbox.ip.tenant.display | The display name of the tenant. | keyword |
| netbox.ip.tenant.id | The unique identifier of the tenant. | long |
| netbox.ip.tenant.name | The name of the tenant. | keyword |
| netbox.ip.tenant.slug | The slug of the tenant. | keyword |
| netbox.ip.tenant.url | The API URL for the tenant. | keyword |
| netbox.ip.url | The API URL for the IP address. | keyword |
| netbox.ip.vrf.description | The description of the VRF. | text |
| netbox.ip.vrf.display | The display name of the VRF. | keyword |
| netbox.ip.vrf.id | The unique identifier of the VRF. | long |
| netbox.ip.vrf.name | The name of the VRF. | keyword |
| netbox.ip.vrf.rd | The route distinguisher of the VRF. | keyword |
| netbox.ip.vrf.url | The API URL for the VRF. | keyword |

