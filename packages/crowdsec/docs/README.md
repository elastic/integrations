# CrowdSec

[CrowdSec](https://www.crowdsec.net/) is an open-source, collaborative intrusion
prevention system. It parses logs, detects aggressive behaviour with scenarios,
and issues remediation decisions such as banning a source IP.

This integration collects CrowdSec **alerts**. Each alert is one detection: the
scenario that fired, the source it fired on, the events that contributed to it,
and the remediation decisions attached. One Elasticsearch document is created per
alert.

## Compatibility

Tested against CrowdSec 1.8.x. The alert structure is stable across 1.x releases.

## Data collection

The integration offers two inputs:

- **HTTP push** — CrowdSec's `notification-http` plugin posts alerts to a listener
  the Elastic Agent runs. This is the real-time path and needs no credentials on
  the Agent side. It is the recommended input.
- **File** — read alerts from a file, one JSON alert object per line. Useful for
  replaying captured alerts.

### Configure the HTTP push in CrowdSec

1. Edit `/etc/crowdsec/notifications/http.yaml`:
   - set `url` to `http://<agent-host>:<port><path>`, matching the listen port and
     URL path configured in this integration (default port `7822`, path `/crowdsec`);
   - keep `format: |` as `{{.|toJson}}` so the full alert objects are sent;
   - optionally add a header and set the same **secret header** in this integration.
2. In `/etc/crowdsec/profiles.yaml`, add `http_default` under `notifications:` for
   the profiles whose alerts you want to collect.
3. Restart CrowdSec.

CrowdSec posts a JSON array of alerts; the HTTP endpoint input creates one event
per array element, so no additional splitting is required.

## Geolocation

CrowdSec includes a country code and coordinates on the alert source. The pipeline
runs the Elastic GeoIP processor on `source.ip` first and falls back to CrowdSec's
own geo only when the database returns nothing — the usual case for offline
installs and for sources the database does not know.

## Dashboard

The **[Logs CrowdSec] Alerts overview** dashboard shows the ban rate, alerts over
time by scenario and decision, a source map, and top talkers, scenarios and target
paths, with a drill-down table of recent alerts. The top controls filter by
scenario, decision type and source country.

## Alerts

### Alert

The `alert` data stream collects CrowdSec alerts.

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2026-09-06T07:10:00.100Z",
    "crowdsec": {
        "alert": {
            "paths": [
                "/products?id=1' OR '1'='1"
            ],
            "status": [
                "403"
            ],
            "target_uri": [
                "/products?id=1' OR '1'='1"
            ],
            "uuid": "aaaa1111-bbbb-2222-cccc-333344445555"
        },
        "capacity": 5,
        "decision": {
            "duration": "4h",
            "origin": "crowdsec",
            "scope": "Ip",
            "type": "ban"
        },
        "decisions": [
            {
                "duration": "4h",
                "origin": "crowdsec",
                "scenario": "crowdsecurity/http-sqli-probing",
                "scope": "Ip",
                "type": "ban",
                "uuid": "d1",
                "value": "203.0.113.240"
            }
        ],
        "events_count": 6,
        "kind": "crowdsec",
        "leakspeed": "10s",
        "machine_id": "gw-paris-01",
        "remediation": true,
        "scenario": {
            "hash": "deadbeef",
            "name": "crowdsecurity/http-sqli-probing",
            "version": "0.2"
        },
        "simulated": false,
        "source": {
            "range": "203.0.113.0/24",
            "scope": "Ip"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "ban",
        "category": [
            "intrusion_detection"
        ],
        "end": "2026-09-06T07:10:03.200Z",
        "id": "aaaa1111-bbbb-2222-cccc-333344445555",
        "kind": "alert",
        "reason": "Ip 203.0.113.240 performed 'crowdsecurity/http-sqli-probing' (6 events)",
        "start": "2026-09-06T07:10:00.100Z",
        "type": [
            "denied"
        ],
        "dataset": "crowdsec.alert",
        "module": "crowdsec"
    },
    "http": {
        "request": {
            "method": [
                "GET"
            ]
        }
    },
    "observer": {
        "name": "gw-paris-01",
        "product": "CrowdSec",
        "type": "ips",
        "vendor": "CrowdSec"
    },
    "related": {
        "ip": [
            "203.0.113.240"
        ]
    },
    "rule": {
        "name": "crowdsecurity/http-sqli-probing",
        "ruleset": "CrowdSec Hub",
        "version": "0.2"
    },
    "source": {
        "address": "203.0.113.240",
        "as": {
            "number": 3215,
            "organization": {
                "name": "Orange S.A."
            }
        },
        "geo": {
            "city_name": "Madrid",
            "continent_name": "Europe",
            "country_iso_code": "ES",
            "country_name": "Spain",
            "location": {
                "lat": 40.41639,
                "lon": -3.7025
            },
            "region_iso_code": "ES-M",
            "region_name": "Madrid"
        },
        "ip": "203.0.113.240"
    },
    "user_agent": {
        "original": [
            "sqlmap/1.7"
        ]
    },
    "data_stream": {
        "type": "logs",
        "dataset": "crowdsec.alert",
        "namespace": "default"
    },
    "tags": [
        "crowdsec-alert",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| crowdsec.alert.paths | Distinct request paths collected from the alert's events. | keyword |
| crowdsec.alert.status | Distinct HTTP status codes seen across the alert's events. | keyword |
| crowdsec.alert.target_uri | Distinct request URIs seen across the events that contributed to the alert. | keyword |
| crowdsec.alert.uuid | Unique identifier of the alert. | keyword |
| crowdsec.capacity | The bucket capacity of the scenario that fired, i.e. how many events it holds before overflowing. | long |
| crowdsec.decision.duration | How long the primary remediation lasts, for example `4h`. | keyword |
| crowdsec.decision.origin | Origin of the primary decision, for example `crowdsec` or `CAPI`. | keyword |
| crowdsec.decision.scope | Scope of the primary decision, for example `Ip` or `Range`. | keyword |
| crowdsec.decision.type | Type of the primary remediation, for example `ban` or `captcha`. | keyword |
| crowdsec.decisions | The full list of remediation decisions carried by the alert. | flattened |
| crowdsec.events_count | Number of events that contributed to the alert. | long |
| crowdsec.kind | The kind of object CrowdSec emitted. Always `crowdsec` for an alert. | keyword |
| crowdsec.leakspeed | The rate at which the scenario bucket leaks events, for example `10s`. | keyword |
| crowdsec.machine_id | Identifier of the CrowdSec machine that raised the alert. | keyword |
| crowdsec.remediation | Whether the alert carries a remediation decision. | boolean |
| crowdsec.scenario.author | Author namespace of the Hub scenario, for example `crowdsecurity` for official scenarios or a community handle. | keyword |
| crowdsec.scenario.hash | Hash of the scenario definition at the time it fired. | keyword |
| crowdsec.scenario.name | Name of the scenario that fired, for example `crowdsecurity/http-probing`. | keyword |
| crowdsec.scenario.title | Scenario name without its author prefix, for example `http-probing`. Used for display. | keyword |
| crowdsec.scenario.version | Version of the scenario. | keyword |
| crowdsec.simulated | Whether the alert was produced in simulation mode and carries no enforced decision. | boolean |
| crowdsec.source.range | The CIDR range the source belongs to, when CrowdSec resolved one. | keyword |
| crowdsec.source.scope | Scope of the alert source, for example `Ip`, `Range` or `Country`. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.status_code | HTTP response status code. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| rule.version | The version / revision of the rule being used for analysis. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |

