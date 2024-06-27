# Cloudflare Integration

Cloudflare integration uses [Cloudflare's API](https://api.cloudflare.com/) to retrieve [audit logs](https://support.cloudflare.com/hc/en-us/articles/115002833612-Understanding-Cloudflare-Audit-Logs) and [traffic logs](https://developers.cloudflare.com/logs/logpull/understanding-the-basics/) from Cloudflare, for a particular zone, and ingest them into Elasticsearch. This allows you to search, observe and visualize the Cloudflare log events through Elasticsearch.

Users of [Cloudflare](https://www.cloudflare.com/en-au/learning/what-is-cloudflare/) use Cloudflare services to increase the security and performance of their web sites and services. 

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In the "Search for integrations" search bar type **Cloudflare**.
3. Click on "Cloudflare" integration from the search results.
4. Click on **Add Cloudflare** button to add Cloudflare integration.

### Configure Cloudflare audit logs data stream

Enter values "Auth Email", "Auth Key" and "Account ID".

1. **Auth Email** is the email address associated with your account. 
2. [**Auth Key**](https://developers.cloudflare.com/api/keys/) is the API key generated on the "My Account" page.
3. **Account ID** can be found on the Cloudflare dashboard. Follow the navigation documentation from [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

NOTE: See for `X-AUTH-EMAIL` and `X-AUTH-KEY` [here](https://api.cloudflare.com/#getting-started-requests) for more information on Auth Email and Auth Key.

### Configure Cloudflare logs

These logs contain data related to the connecting client, the request path through the Cloudflare network, and the response from the origin web server. For more information see [here](https://developers.cloudflare.com/logs/logpull/).

The integration can retrieve Cloudflare logs using -

1. Auth Email and Auth Key
2. API Token

More information is available [here](https://developers.cloudflare.com/logs/logpull/requesting-logs/#required-authentication-headers)

#### Configure using Auth Email and Auth Key

Enter values "Auth Email", "Auth Key" and "Zone ID".

1. **Auth Email** is the email address associated with your account. 
2. [**Auth Key**](https://developers.cloudflare.com/api/keys/) is the API key generated on the "My Account" page.
3. **Zone ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

>  Note: See for `X-AUTH-EMAIL` and `X-AUTH-KEY` [here](https://api.cloudflare.com/#getting-started-requests) for more information on Auth Email and Auth Key.

#### Configure using API Token

Enter values "API Token" and "Zone ID".

For the Cloudflare integration to be able to successfully get logs the following permissions must be granted to the API token -

- Account.Access: Audit Logs: Read

1. [**API Tokens**](https://developers.cloudflare.com/api/tokens/) allow for more granular permission settings. 
2. **Zone ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

## Logs

### Audit

Audit logs summarize the history of changes made within your Cloudflare account.  Audit logs include account-level actions like login and logout, as well as setting changes to DNS, Crypto, Firewall, Speed, Caching, Page Rules, Network, and Traffic features, etc.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare.audit.actor.type | The type of actor, whether a User, Cloudflare Admin, or an Automated System. Valid values: user, admin, Cloudflare. | keyword |
| cloudflare.audit.metadata | An object which can lend more context to the action being logged. This is a flexible value and varies between different actions. | flattened |
| cloudflare.audit.new_value | The new value of the resource that was modified | flattened |
| cloudflare.audit.old_value | The value of the resource before it was modified | flattened |
| cloudflare.audit.owner.id | User identifier tag | keyword |
| cloudflare.audit.resource.id | An identifier for the resource that was affected by the action | keyword |
| cloudflare.audit.resource.type | A short string that describes the resource that was affected by the action | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-30T13:42:04.000Z",
    "agent": {
        "ephemeral_id": "c1f5062e-f467-4812-af6a-7d4b4e7c942d",
        "id": "4b6522ee-8519-493a-b53a-a85672045358",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "cloud": {
        "account": {
            "id": "aaabbbccc"
        },
        "provider": "cloudflare"
    },
    "cloudflare": {
        "audit": {
            "actor": {
                "type": "user"
            },
            "owner": {
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s"
            },
            "resource": {
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s",
                "type": "account"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4b6522ee-8519-493a-b53a-a85672045358",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "rotate_api_key",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2023-10-10T14:41:04.679Z",
        "dataset": "cloudflare.audit",
        "id": "8d3396e8-c903-5a66-9421-00fc34570550",
        "ingested": "2023-10-10T14:41:05Z",
        "kind": "event",
        "original": "{\"action\":{\"info\":\"key digest: c6b5d100d7ce492d24c5b13160fce1cc0092ce7e8d8430e9f5cf5468868be6f6\",\"result\":true,\"type\":\"rotate_API_key\"},\"actor\":{\"email\":\"user@example.com\",\"id\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ip\":\"52.91.36.10\",\"type\":\"user\"},\"id\":\"8d3396e8-c903-5a66-9421-00fc34570550\",\"interface\":\"\",\"metadata\":{},\"newValue\":\"\",\"oldValue\":\"\",\"owner\":{\"id\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\"},\"resource\":{\"id\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"type\":\"account\"},\"when\":\"2021-11-30T13:42:04Z\"}",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "52.91.36.10"
        ],
        "user": [
            "enl3j9du8rnx2swwd9l32qots7l54t9s"
        ]
    },
    "source": {
        "address": "52.91.36.10",
        "ip": "52.91.36.10"
    },
    "tags": [
        "forwarded",
        "cloudflare-audit",
        "preserve_original_event"
    ],
    "user": {
        "email": "user@example.com",
        "id": "enl3j9du8rnx2swwd9l32qots7l54t9s"
    }
}

```

### Logpull

These logs contain data related to the connecting client, the request path through the Cloudflare network, and the response from the origin web server. For more information see [here](https://developers.cloudflare.com/logs/logpull/).

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloudflare.bot.score.src | Detection engine responsible for generating the Bot Score. Possible values are Not Computed, Heuristics, Machine Learning, Behavioral Analysis, Verified Bot, JS Fingerprinting, Cloudflare Service. | text |
| cloudflare.bot.score.value | Cloudflare Bot Score. Scores below 30 are commonly associated with automated traffic. | long |
| cloudflare.cache.bytes | Number of bytes returned by the cache | long |
| cloudflare.cache.status | Status of cache | keyword |
| cloudflare.cache.status_code | HTTP status code returned by the cache to the edge. All requests (including non-cacheable ones) go through the cache. | long |
| cloudflare.cache.tiered_fill | Tiered Cache was used to serve this request | boolean |
| cloudflare.client.ip_class | Class of client, ex. badHost | searchEngine | allowlist | greylist.... | keyword |
| cloudflare.client.ssl.protocol | Client SSL (TLS) protocol | keyword |
| cloudflare.device_type | Client device type | keyword |
| cloudflare.edge.colo.code | IATA airport code of data center that received the request | keyword |
| cloudflare.edge.colo.id | Cloudflare edge colo id | long |
| cloudflare.edge.pathing.op | Indicates what type of response was issued for this request (unknown = no specific action) | keyword |
| cloudflare.edge.pathing.src | Details how the request was classified based on security checks (unknown = no specific classification) | keyword |
| cloudflare.edge.pathing.status | Indicates what data was used to determine the handling of this request (unknown = no data) | keyword |
| cloudflare.edge.rate_limit.action | The action taken by the blocking rule; empty if no action taken | keyword |
| cloudflare.edge.rate_limit.id | The internal rule ID of the rate-limiting rule that triggered a block (ban) or log action. 0 if no action taken. | long |
| cloudflare.edge.request.host | Host header on the request from the edge to the origin | keyword |
| cloudflare.edge.response.bytes | Number of bytes returned by the edge to the client | long |
| cloudflare.edge.response.compression_ratio | Edge response compression ratio | long |
| cloudflare.edge.response.content_type | Edge response Content-Type header value | keyword |
| cloudflare.edge.response.status_code | HTTP status code returned by Cloudflare to the client | long |
| cloudflare.firewall.actions | Array of actions the Cloudflare firewall products performed on this request. The individual firewall products associated with this action be found in FirewallMatchesSources and their respective RuleIds can be found in FirewallMatchesRuleIDs. The length of the array is the same as FirewallMatchesRuleIDs and FirewallMatchesSources. | keyword |
| cloudflare.firewall.rule_ids | Array of RuleIDs of the firewall product that has matched the request. The firewall product associated with the RuleID can be found in FirewallMatchesSources. The length of the array is the same as FirewallMatchesActions and FirewallMatchesSources. | keyword |
| cloudflare.firewall.sources | The firewall products that matched the request. The same product can appear multiple times, which indicates different rules or actions that were activated. The RuleIDs can be found in FirewallMatchesRuleIDs, the actions can be found in FirewallMatchesActions. The length of the array is the same as FirewallMatchesRuleIDs and FirewallMatchesActions. | keyword |
| cloudflare.origin.response.bytes | Number of bytes returned by the origin server | long |
| cloudflare.origin.response.expires | Value of the origin 'expires' header | date |
| cloudflare.origin.response.last_modified | Value of the origin 'last-modified' header | date |
| cloudflare.origin.response.status_code | Status returned by the origin server | long |
| cloudflare.origin.response.time | Number of nanoseconds it took the origin to return the response to edge | long |
| cloudflare.origin.ssl.protocol | SSL (TLS) protocol used to connect to the origin | keyword |
| cloudflare.parent.ray_id | Ray ID of the parent request if this request was made using a Worker script | keyword |
| cloudflare.ray_id | Ray ID of the parent request if this request was made using a Worker script | keyword |
| cloudflare.security_level | The security level configured at the time of this request. This is used to determine the sensitivity of the IP Reputation system. | keyword |
| cloudflare.waf.action | Action taken by the WAF, if triggered | keyword |
| cloudflare.waf.flags | Additional configuration flags: simulate (0x1) | null | keyword |
| cloudflare.waf.matched_var | The full name of the most-recently matched variable | keyword |
| cloudflare.waf.profile | low | med | high | keyword |
| cloudflare.waf.rule.id | ID of the applied WAF rule | keyword |
| cloudflare.waf.rule.message | Rule message associated with the triggered rule | keyword |
| cloudflare.worker.cpu_time | Amount of time in microseconds spent executing a worker, if any | long |
| cloudflare.worker.status | Status returned from worker daemon | keyword |
| cloudflare.worker.subrequest | Whether or not this request was a worker subrequest | boolean |
| cloudflare.worker.subrequest_count | Number of subrequests issued by a worker when handling this request | long |
| cloudflare.zone.id | Internal zone ID | long |
| cloudflare.zone.name | The human-readable name of the zone (e.g. 'cloudflare.com'). | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `logpull` looks as following:

```json
{
    "@timestamp": "2019-08-02T15:29:08.000Z",
    "agent": {
        "ephemeral_id": "a27dd9de-634b-47ac-a284-09aaea297972",
        "id": "4b6522ee-8519-493a-b53a-a85672045358",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "client": {
        "address": "35.232.161.245",
        "as": {
            "number": 15169
        },
        "bytes": 2577,
        "geo": {
            "country_iso_code": "us"
        },
        "ip": "35.232.161.245",
        "port": 55028
    },
    "cloudflare": {
        "cache": {
            "status": "unknown",
            "tiered_fill": false
        },
        "client": {
            "ip_class": "noRecord",
            "ssl": {
                "protocol": "TLSv1.2"
            }
        },
        "device_type": "desktop",
        "edge": {
            "colo": {
                "id": 14
            },
            "pathing": {
                "op": "wl",
                "src": "filter_based_firewall",
                "status": "captchaNew"
            },
            "rate_limit": {
                "id": 0
            },
            "response": {
                "bytes": 2848,
                "compression_ratio": 2.64,
                "content_type": "text/html",
                "status_code": 403
            }
        },
        "firewall": {
            "actions": [
                "simulate",
                "challenge"
            ],
            "rule_ids": [
                "094b71fea25d4860a61fa0c6fbbd8d8b",
                "e454fd4a0ce546b3a9a462536613692c"
            ],
            "sources": [
                "firewallRules",
                "firewallRules"
            ]
        },
        "origin": {
            "response": {
                "bytes": 0,
                "status_code": 0,
                "time": 0
            },
            "ssl": {
                "protocol": "unknown"
            }
        },
        "parent": {
            "ray_id": "00"
        },
        "ray_id": "500115ec386354d8",
        "security_level": "med",
        "waf": {
            "action": "unknown",
            "flags": "0",
            "profile": "unknown"
        },
        "worker": {
            "cpu_time": 0,
            "status": "unknown",
            "subrequest": false,
            "subrequest_count": 0
        },
        "zone": {
            "id": 155978002
        }
    },
    "data_stream": {
        "dataset": "cloudflare.logpull",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 2848
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4b6522ee-8519-493a-b53a-a85672045358",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": [
            "simulate",
            "challenge"
        ],
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-10-10T14:42:46.310Z",
        "dataset": "cloudflare.logpull",
        "duration": 0,
        "end": "2019-08-02T15:29:08.000Z",
        "ingested": "2023-10-10T14:42:49Z",
        "kind": "event",
        "original": "{\"CacheCacheStatus\":\"unknown\",\"CacheResponseBytes\":0,\"CacheResponseStatus\":0,\"CacheTieredFill\":false,\"ClientASN\":15169,\"ClientCountry\":\"us\",\"ClientDeviceType\":\"desktop\",\"ClientIP\":\"35.232.161.245\",\"ClientIPClass\":\"noRecord\",\"ClientRequestBytes\":2577,\"ClientRequestHost\":\"cf-analytics.com\",\"ClientRequestMethod\":\"POST\",\"ClientRequestPath\":\"/wp-cron.php\",\"ClientRequestProtocol\":\"HTTP/1.1\",\"ClientRequestReferer\":\"https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000\",\"ClientRequestURI\":\"/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000\",\"ClientRequestUserAgent\":\"WordPress/5.2.2;https://cf-analytics.com\",\"ClientSSLCipher\":\"ECDHE-ECDSA-AES128-GCM-SHA256\",\"ClientSSLProtocol\":\"TLSv1.2\",\"ClientSrcPort\":55028,\"EdgeColoID\":14,\"EdgeEndTimestamp\":\"2019-08-02T15:29:08Z\",\"EdgePathingOp\":\"wl\",\"EdgePathingSrc\":\"filter_based_firewall\",\"EdgePathingStatus\":\"captchaNew\",\"EdgeRateLimitAction\":\"\",\"EdgeRateLimitID\":0,\"EdgeRequestHost\":\"\",\"EdgeResponseBytes\":2848,\"EdgeResponseCompressionRatio\":2.64,\"EdgeResponseContentType\":\"text/html\",\"EdgeResponseStatus\":403,\"EdgeServerIP\":\"\",\"EdgeStartTimestamp\":\"2019-08-02T15:29:08Z\",\"FirewallMatchesActions\":[\"simulate\",\"challenge\"],\"FirewallMatchesRuleIDs\":[\"094b71fea25d4860a61fa0c6fbbd8d8b\",\"e454fd4a0ce546b3a9a462536613692c\"],\"FirewallMatchesSources\":[\"firewallRules\",\"firewallRules\"],\"OriginIP\":\"\",\"OriginResponseBytes\":0,\"OriginResponseHTTPExpires\":\"\",\"OriginResponseHTTPLastModified\":\"\",\"OriginResponseStatus\":0,\"OriginResponseTime\":0,\"OriginSSLProtocol\":\"unknown\",\"ParentRayID\":\"00\",\"RayID\":\"500115ec386354d8\",\"SecurityLevel\":\"med\",\"WAFAction\":\"unknown\",\"WAFFlags\":\"0\",\"WAFMatchedVar\":\"\",\"WAFProfile\":\"unknown\",\"WAFRuleID\":\"\",\"WAFRuleMessage\":\"\",\"WorkerCPUTime\":0,\"WorkerStatus\":\"unknown\",\"WorkerSubrequest\":false,\"WorkerSubrequestCount\":0,\"ZoneID\":155978002}",
        "start": "2019-08-02T15:29:08.000Z"
    },
    "http": {
        "request": {
            "bytes": 2577,
            "method": "POST",
            "referrer": "https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000"
        },
        "response": {
            "bytes": 2848,
            "status_code": 403
        },
        "version": "1.1"
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "bytes": 5425,
        "protocol": "http",
        "transport": "tcp"
    },
    "observer": {
        "type": "proxy",
        "vendor": "cloudflare"
    },
    "server": {
        "bytes": 2848
    },
    "source": {
        "address": "35.232.161.245",
        "as": {
            "number": 15169
        },
        "bytes": 2577,
        "geo": {
            "country_iso_code": "us"
        },
        "ip": "35.232.161.245",
        "port": 55028
    },
    "tags": [
        "forwarded",
        "cloudflare-logpull",
        "preserve_original_event"
    ],
    "tls": {
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
        "version": "1.2",
        "version_protocol": "tls"
    },
    "url": {
        "domain": "cf-analytics.com",
        "extension": "php",
        "full": "https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000",
        "original": "/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000",
        "path": "/wp-cron.php",
        "query": "doing_wp_cron=1564759748.3962020874023437500000",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Spider"
        },
        "name": "WordPress",
        "original": "WordPress/5.2.2;https://cf-analytics.com",
        "version": "5.2.2"
    }
}

```
