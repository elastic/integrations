# ECE Integration

The ECE Integration collects the Adminconsole logs which contain all actions performed through the admin UI and as well as through the API. The Elastic Agent collecting these logs needs to be installed on all Control Planes in ECE, as the Control Planes usually host the adminconsole container.

## Adminconsole

An example event for `adminconsole` looks as following:

```json
{
    "@timestamp": "2025-05-09T07:43:09.031Z",
    "ece_adminconsole": {
        "log": {
            "deployment": {
                "name": "francis"
            }
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "create_deployment",
        "category": [
            "api"
        ],
        "duration": 1711000000,
        "original": "{\"@timestamp\":\"2025-05-09T07:43:09.031238Z\",\"process\":{\"thread\":{\"name\":\"adminconsole-requests-pekko.actor.default-dispatcher-28\"}},\"message\":\"201 Created - philipp - 6d8ed3ff3ddb495496e1c6752f9feb07 - 127.0.0.1 - 172.17.42.1 - POST 34.147.36.145:12443/api/v1/deployments HTTP/1.1 in:2361 out:unknown (1711 ms)\",\"log\":{\"logger\":\"no.found.adminconsole.http.requests\",\"level\":\"INFO\"},\"proxy_ip\":\"172.17.42.1\",\"query_parameters\":\"validate_only=false\",\"request_url\":\"34.147.36.145:12443/api/v1/deployments\",\"trace.id\":\"\",\"api_key_id\":\"unknown\",\"request_method\":\"POST\",\"commit_hash\":\"8ba74f3d10ab89948c8241c842a8e31d3fc70070\",\"request_host\":\"34.147.36.145\",\"request_length\":\"2361\",\"request_payload\":\"{\\\"name\\\":\\\"francis\\\",\\\"resources\\\":{\\\"elasticsearch\\\":[{\\\"ref_id\\\":\\\"main-elasticsearch\\\",\\\"region\\\":\\\"ece-region\\\",\\\"plan\\\":{\\\"cluster_topology\\\":[{\\\"id\\\":\\\"hot_content\\\",\\\"node_roles\\\":[\\\"master\\\",\\\"ingest\\\",\\\"transform\\\",\\\"data_hot\\\",\\\"remote_cluster_client\\\",\\\"data_content\\\"],\\\"zone_count\\\":1,\\\"elasticsearch\\\":{\\\"node_attributes\\\":{\\\"data\\\":\\\"hot\\\"}},\\\"instance_configuration_id\\\":\\\"data.default\\\",\\\"size\\\":{\\\"value\\\":4096,\\\"resource\\\":\\\"memory\\\"}},{\\\"id\\\":\\\"warm\\\",\\\"node_roles\\\":[\\\"data_warm\\\",\\\"remote_cluster_client\\\"],\\\"zone_count\\\":1,\\\"elasticsearch\\\":{\\\"node_attributes\\\":{\\\"data\\\":\\\"warm\\\"}},\\\"instance_configuration_id\\\":\\\"data.highstorage\\\",\\\"size\\\":{\\\"value\\\":0,\\\"resource\\\":\\\"memory\\\"}},{\\\"id\\\":\\\"cold\\\",\\\"node_roles\\\":[\\\"data_cold\\\",\\\"remote_cluster_client\\\"],\\\"zone_count\\\":1,\\\"elasticsearch\\\":{\\\"node_attributes\\\":{\\\"data\\\":\\\"cold\\\"}},\\\"instance_configuration_id\\\":\\\"data.highstorage\\\",\\\"size\\\":{\\\"value\\\":0,\\\"resource\\\":\\\"memory\\\"}},{\\\"id\\\":\\\"frozen\\\",\\\"node_roles\\\":[\\\"data_frozen\\\"],\\\"zone_count\\\":1,\\\"elasticsearch\\\":{\\\"node_attributes\\\":{\\\"data\\\":\\\"frozen\\\"}},\\\"instance_configuration_id\\\":\\\"data.frozen\\\",\\\"size\\\":{\\\"value\\\":0,\\\"resource\\\":\\\"memory\\\"}},{\\\"id\\\":\\\"coordinating\\\",\\\"node_roles\\\":[\\\"ingest\\\",\\\"remote_cluster_client\\\"],\\\"zone_count\\\":1,\\\"instance_configuration_id\\\":\\\"coordinating\\\",\\\"size\\\":{\\\"value\\\":0,\\\"resource\\\":\\\"memory\\\"}},{\\\"id\\\":\\\"master\\\",\\\"node_roles\\\":[\\\"master\\\",\\\"remote_cluster_client\\\"],\\\"zone_count\\\":1,\\\"instance_configuration_id\\\":\\\"master\\\",\\\"size\\\":{\\\"value\\\":0,\\\"resource\\\":\\\"memory\\\"}},{\\\"id\\\":\\\"ml\\\",\\\"node_roles\\\":[\\\"ml\\\",\\\"remote_cluster_client\\\"],\\\"zone_count\\\":1,\\\"instance_configuration_id\\\":\\\"ml\\\",\\\"size\\\":{\\\"value\\\":1024,\\\"resource\\\":\\\"memory\\\"}}],\\\"elasticsearch\\\":{\\\"version\\\":\\\"8.17.4\\\",\\\"enabled_built_in_plugins\\\":[]},\\\"deployment_template\\\":{\\\"id\\\":\\\"default\\\"}},\\\"settings\\\":{\\\"snapshot\\\":{\\\"enabled\\\":false},\\\"dedicated_masters_threshold\\\":6}}],\\\"kibana\\\":[{\\\"ref_id\\\":\\\"main-kibana\\\",\\\"elasticsearch_cluster_ref_id\\\":\\\"main-elasticsearch\\\",\\\"region\\\":\\\"ece-region\\\",\\\"plan\\\":{\\\"cluster_topology\\\":[{\\\"instance_configuration_id\\\":\\\"kibana\\\",\\\"size\\\":{\\\"value\\\":1024,\\\"resource\\\":\\\"memory\\\"},\\\"zone_count\\\":1}],\\\"kibana\\\":{\\\"version\\\":\\\"8.17.4\\\"}}}],\\\"enterprise_search\\\":[],\\\"integrations_server\\\":[{\\\"ref_id\\\":\\\"main-integrations_server\\\",\\\"elasticsearch_cluster_ref_id\\\":\\\"main-elasticsearch\\\",\\\"region\\\":\\\"ece-region\\\",\\\"plan\\\":{\\\"cluster_topology\\\":[{\\\"instance_configuration_id\\\":\\\"integrations.server\\\",\\\"size\\\":{\\\"value\\\":512,\\\"resource\\\":\\\"memory\\\"},\\\"zone_count\\\":1}],\\\"integrations_server\\\":{\\\"version\\\":\\\"8.17.4\\\"}}}]},\\\"settings\\\":{\\\"autoscaling_enabled\\\":false},\\\"metadata\\\":{\\\"system_owned\\\":false}}\",\"auth_type\":\"cookie\",\"status_code\":\"201\",\"auth_user\":\"philipp\",\"response_time\":\"1711\",\"user_agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36\",\"request_id\":\"2271905ee3f6e6cc9c76a0c7cccfd1cc\",\"organization_id\":\"6d8ed3ff3ddb495496e1c6752f9feb07\",\"transaction.id\":\"\",\"client_ip\":\"127.0.0.1\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "body": {
                "bytes": 2361,
                "content": "{\"name\":\"francis\",\"resources\":{\"elasticsearch\":[{\"ref_id\":\"main-elasticsearch\",\"region\":\"ece-region\",\"plan\":{\"cluster_topology\":[{\"id\":\"hot_content\",\"node_roles\":[\"master\",\"ingest\",\"transform\",\"data_hot\",\"remote_cluster_client\",\"data_content\"],\"zone_count\":1,\"elasticsearch\":{\"node_attributes\":{\"data\":\"hot\"}},\"instance_configuration_id\":\"data.default\",\"size\":{\"value\":4096,\"resource\":\"memory\"}},{\"id\":\"warm\",\"node_roles\":[\"data_warm\",\"remote_cluster_client\"],\"zone_count\":1,\"elasticsearch\":{\"node_attributes\":{\"data\":\"warm\"}},\"instance_configuration_id\":\"data.highstorage\",\"size\":{\"value\":0,\"resource\":\"memory\"}},{\"id\":\"cold\",\"node_roles\":[\"data_cold\",\"remote_cluster_client\"],\"zone_count\":1,\"elasticsearch\":{\"node_attributes\":{\"data\":\"cold\"}},\"instance_configuration_id\":\"data.highstorage\",\"size\":{\"value\":0,\"resource\":\"memory\"}},{\"id\":\"frozen\",\"node_roles\":[\"data_frozen\"],\"zone_count\":1,\"elasticsearch\":{\"node_attributes\":{\"data\":\"frozen\"}},\"instance_configuration_id\":\"data.frozen\",\"size\":{\"value\":0,\"resource\":\"memory\"}},{\"id\":\"coordinating\",\"node_roles\":[\"ingest\",\"remote_cluster_client\"],\"zone_count\":1,\"instance_configuration_id\":\"coordinating\",\"size\":{\"value\":0,\"resource\":\"memory\"}},{\"id\":\"master\",\"node_roles\":[\"master\",\"remote_cluster_client\"],\"zone_count\":1,\"instance_configuration_id\":\"master\",\"size\":{\"value\":0,\"resource\":\"memory\"}},{\"id\":\"ml\",\"node_roles\":[\"ml\",\"remote_cluster_client\"],\"zone_count\":1,\"instance_configuration_id\":\"ml\",\"size\":{\"value\":1024,\"resource\":\"memory\"}}],\"elasticsearch\":{\"version\":\"8.17.4\",\"enabled_built_in_plugins\":[]},\"deployment_template\":{\"id\":\"default\"}},\"settings\":{\"snapshot\":{\"enabled\":false},\"dedicated_masters_threshold\":6}}],\"kibana\":[{\"ref_id\":\"main-kibana\",\"elasticsearch_cluster_ref_id\":\"main-elasticsearch\",\"region\":\"ece-region\",\"plan\":{\"cluster_topology\":[{\"instance_configuration_id\":\"kibana\",\"size\":{\"value\":1024,\"resource\":\"memory\"},\"zone_count\":1}],\"kibana\":{\"version\":\"8.17.4\"}}}],\"enterprise_search\":[],\"integrations_server\":[{\"ref_id\":\"main-integrations_server\",\"elasticsearch_cluster_ref_id\":\"main-elasticsearch\",\"region\":\"ece-region\",\"plan\":{\"cluster_topology\":[{\"instance_configuration_id\":\"integrations.server\",\"size\":{\"value\":512,\"resource\":\"memory\"},\"zone_count\":1}],\"integrations_server\":{\"version\":\"8.17.4\"}}}]},\"settings\":{\"autoscaling_enabled\":false},\"metadata\":{\"system_owned\":false}}"
            },
            "id": "2271905ee3f6e6cc9c76a0c7cccfd1cc",
            "method": "POST"
        },
        "response": {
            "status_code": 201
        }
    },
    "log": {
        "level": "INFO",
        "logger": "no.found.adminconsole.http.requests"
    },
    "message": "201 Created - philipp - 6d8ed3ff3ddb495496e1c6752f9feb07 - 127.0.0.1 - 172.17.42.1 - POST 34.147.36.145:12443/api/v1/deployments HTTP/1.1 in:2361 out:unknown (1711 ms)",
    "network": {
        "forwarded_ip": "172.17.42.1"
    },
    "organization": {
        "id": "6d8ed3ff3ddb495496e1c6752f9feb07"
    },
    "process": {
        "thread": {
            "name": "adminconsole-requests-pekko.actor.default-dispatcher-28"
        }
    },
    "related": {
        "hosts": [
            "34.147.36.145"
        ],
        "ip": [
            "172.17.42.1",
            "127.0.0.1"
        ],
        "user": [
            "philipp"
        ]
    },
    "source": {
        "ip": "127.0.0.1"
    },
    "url": {
        "domain": "34.147.36.145",
        "original": "https://34.147.36.145:12443/api/v1/deployments",
        "path": "/api/v1/deployments",
        "port": 12443,
        "scheme": "https"
    },
    "user": {
        "name": "philipp"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "138.0.0.0"
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
| ece_adminconsole.log.deployment.es_api |  | keyword |
| ece_adminconsole.log.deployment.id |  | keyword |
| ece_adminconsole.log.deployment.name |  | keyword |

