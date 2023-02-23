# Shodan Integration

[Shodan](https://shodan.io/) provides data about hosts that Shodan crawlers have observed and scanned on the Internet.

Shodan supports sending notifications about potentially security relevant events related to DNS names and IP addresses from the Shodan Monitor service.

## Compatability

Host data can be requested via the [Shodan API](https://developer.shodan.io/api) host search endpoint, which this integration can query.

Host data is included in notifications sent by the [Shodan Monitor](https://monitor.shodan.io/) service, which this integration can receive as webhooks, aka. HTTP JSON POST.

The host object in a webhook is the same as that returned from the [Shodan API](https://developer.shodan.io/api) host search endpoint. Due to this a single data stream is used for storage of both types of documents.

Be aware, that data from Shodan is inconsistent in both type and structure, and requires a complicated ingest pipeline to munge it to a format that will likely be accepted by Elastic.

The integration has been tested against 300,000 records returned by the Shodan API in response to the search for country:AU, in order to validate the ingest pipeline and index template.

However, the following challenges exist, that will likely result in lost events in future.

### Shodan data storage does not appear to differentiate between numeric, string or object.

It has no schema. It is timeless, formless, and so is all things at all times. Because Shodan.

Exhibit A, a string that may be null, or may be a number.

```
user@box shodan % cat _dev/deploy/docker/sample_logs/shodan-download.ndjson | jq '.ntp.version' 2>/dev/null | grep -v -e ^$ -e null| sort -u 
"\"4\""
"\"ntpd 4.2.0-a Thu Mar 10 07:17:22  2022 (1)\""
3
4
user@box shodan % 
```

Exhibit B, a string that may be null, or may be a number.

```
user@box shodan % cat _dev/deploy/docker/sample_logs/shodan-download.ndjson | jq '.ssl.dhparams.generator' 2>/dev/null | grep -v -e ^$ -e null | sort -u
"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
"48dd0add656738915845d5de5648d346df2680b0cf4d80b0b30e3754847444ae377577fdef069384a6370ca6d2bdff3723da76f99953e5cc4dc0fe716081207ec51a64c667107dd4717cacbeaff1fa493e0267fce001083bad6d51ddeae6cab7a6582bb29212035e5cb06eca17c1a7dce7eb76f31476b7ca81962d2459e4869683d457b890ca5be493f2bfacf7a08d860576835667e436c90df6ac97919410fc0bb275133f32c9c00bff520b59ca581f08ecf5508ab3db8129c5c1e19c3e5104020f95887ddb4f03ca53922f5915947c72184297b5b9a83c68c929abdf342c6051bdd2a888f220d6c9635bb48327970e0b7594ad44cfbfe0df4e13e84dc9c803"
2
user@box shodan % 
```

Exhibit C, a value that may be null, may be a string, or may be an object.

```
user@box shodan % cat _dev/deploy/docker/sample_logs/shodan-download.ndjson | jq --monochrome-output --compact-output '.minecraft.description' | head -n 10
{"text":"§lTekkit 2 Server v1.1.3"}
"Dad Jules Server World"
null
{"text":"Java Edition"}
{"text":"§d§oSevTech: Ages Server§r - §4v3.2.3"}
{"text":"","extra":[{"color":"white","text":"Idiot Bar"},{"color":"green","text":" Season 6"}]}
"§bTeva & Zoeys GTNH server!§r\ngreg time"
null
null
{"text":"","extra":[{"color":"white","text":"         ✿"},{"color":"dark_purple","text":" W"},{"color":"light_purple","text":"e"},{"color":"dark_purple","text":"l"},{"color":"light_purple","text":"c"},{"color":"dark_purple","text":"o"},{"color":"light_purple","text":"m"},{"color":"dark_purple","text":"e"},{"color":"light_purple","text":" t"},{"color":"dark_purple","text":"o"},{"color":"light_purple","text":" A"},{"color":"dark_purple","text":"s"},{"color":"light_purple","text":"p"},{"color":"dark_purple","text":"e"},{"color":"light_purple","text":"r"},{"color":"dark_purple","text":"i"},{"color":"light_purple","text":"e"},{"color":"dark_purple","text":"n"},{"color":"white","text":" ✿"},{"text":"\n"},{"color":"white","text":"│ "},{"color":"red","text":"Survival"},{"color":"white","text":" │ "},{"color":"gold","text":"Towny"},{"color":"white","text":" │ "},{"color":"green","text":"MCMMO"},{"color":"white","text":" │"},{"color":"aqua","text":" PVPArenas"},{"color":"white","text":" │"}]}
user@box shodan %
```

Exhibit D, a list that contains both IP strings and numbers.

```
user@box shodan % grep redis shodan-country-AU-1.ndjson | jq --monochrome-output --compact-output '.redis.clients[].addr' 2>/dev/null | sort -u | head -n 10
["10.42.0.0",22015]
["10.42.0.0",35290]
["10.42.0.0",60412]
["10.42.0.0",64159]
["10.42.0.0",8761]
["10.42.1.74",44942]
["10.42.1.74",44944]
["104.152.52.103",52627]
["120.79.201.241",36398]
["127.0.0.1",53403]
user@box shodan %
```

We currently iterate thru the entire "JSON" parsed payload, and convert any value we find that's not already a string or an object, to be a string for the above reasons.

We currently do special things to handle,
* `shodan.host.ssl.trust.revoked` <<< which is renamed to shodan.host.ssl.trust.is_revoked if it's a boolean or string type value, if it's an object it is left as shodan.host.ssl.trust.revoked
* `shodan.host.minecraft.description` <<< which is forced to be a string regardless of what it already is. The result is an escaped JSON object as a string.

Monitor your Elastic Agent logs for errors, for instance based on a search for `( data_stream.dataset : "elastic_agent.filebeat" AND log.level: ( error OR warning OR warn ) AND message: "Cannot index event*" ) OR error.message: *`.

### Shodan data storage utilises 128-bit or larger numeric values

In particular, instead of storing things like SHA1, MD5, SHA256 hashes as hex based text strings as the rest of the world does, Shodan does [does it another way](https://help.shodan.io/mastery/property-hashes).

They appear to have used [Murmur3](https://en.wikipedia.org/wiki/MurmurHash) or a similar hashing method which results in a 128-bit value at times, or 64-bit, or even 32-bit; in order to save a very small amount of data storage for each event.

1. The rest of known world hash example: `"f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"`
2. Shodan hash example: `13878014086658349096377801728614327767`

Shodan sends their hash values in the webhook JSON payload as integers, not as strings.

Elasticsearch [can store up to a 64-bit integer value using long/unsigned long](https://www.elastic.co/guide/en/elasticsearch/reference/current/number.html), but cannot at this point, store a 128-bit integer value in any way that would retain it as usable.

Example indexing error if 128-bit values are received,

`Numeric value (13878014086658349096377801728614327767) out of range of long (-9223372036854775808 - 9223372036854775807)`

So these types of values from Shodan need to be stored as strings, and the ingest pipeline currently converts everything to a string, so this should be resolved however future hash fields that appear, and which are not explicitly defined in the index template, may result in an automatic field type long due to the first few events seen; and ingest failures for subsequent events where the number is too large.

The following are known 128-bit hash bearing fields,
* json.ftp.features_hash
* json.hash
* json.http.headers_hash
* json.http.html_hash
* json.http.favicon.hash
* json.http.robots_hash
* json.http.securitytxt_hash
* json.http.sitemap_hash
* json.opts.screenshot.hash
* json.screenshot.hash
* json.ssl.cert.serial

Monitor your Elastic Agent logs for errors, for instance based on a search for `( data_stream.dataset : "elastic_agent.filebeat" AND log.level: ( error OR warning OR warn ) AND message: "Cannot index event*" ) OR error.message: *`.

### The Shodan API may or may not send a complete JSON response, as at times the payload is truncated, for unknown reasons.

This is probably due to web infrastructure failure, or backend failures in some way, leading to TCP connection chops. That's my best guess anyway.

Be aware though, if you're seeing a lower host count in Elastic, that this may be the cause.

Monitor your Elastic Agent logs for errors talking to the API if this is of concern to you.

### Pagination in the Shodan API is as simple as pagination could be, but it is simultaneously unreliable and the API often has no idea how many results there really should be.

Pagination is [described here](https://developer.shodan.io/api), but in summary, if you submit a search, on the first page of the results you get told how many results there should be in total via the `.total` field in the JSON response.

Pagination is always in 100 result blocks, so page 1 *should have* 100 results.

Subsequent requests should request page=N, to receive another 100 results, so keep incrementing page=N until you have all results.

This *does* seem to work, kind of as you won't always get exactly 100 results for any page not just the last one, however sometimes the total received in response is inconsistent.

For example, sometimes on page 1 you receive a "total" value indicating there is 6515 results, however on all subsequent requests the total is *always* 3896.

As below, on page 1 thru 40 for set of results previously downloaded to file from API,

```
user@box shodan % cat get.sh 
#!/bin/bash

PAGE=1

while true ; do
  echo "Getting page ${PAGE}..."
  curl --silent \
    --output "page_${PAGE}.json" \
    "https://api.shodan.io/shodan/host/search?key=REPLACED&query=org:\"REPLACED\"&page=${PAGE}"

  RESULTS=`cat page_${PAGE}.json | jq --monochrome-output --compact-output '.matches[]' 2>&1`

  if [ "${RESULTS}x" != "x" ] ; then
    PAGE=$((${PAGE}+1))
  else
    exit 0
  fi
done
user@box shodan % 

user@box shodan % sh get.sh 
Getting page 1...
Getting page 2...
%{BREVITY}%
Getting page 39...
Getting page 40...
user@box shodan % 

user@box shodan % for i in `seq 1 40` ; do sed -r -e 's/^.*"total"\:/"total":/' page_${i}.json ; echo ; done
"total": 6515}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
"total": 3896}
user@box shodan % 
```

This *may* be due to CloudFlare routing different requests to different locations due to congestion, latency, other network failures, etc; so that the request lands on different infrastructure with the Shodan data set in a slightly different state.

I suspect, for instance, that synchronisation of data between their EU and NA crawler infrastructure and/or between data storage locations is the main cause.

This is one reason why the httpjson input ignores total and simply keeps requesting new pages until .matches == [] indicating there is no further results.

The downside is that this consumes an extra API credit, and that you may not see the data you expect or hope to see in Elastic based on what you found in the Shodan web interface, until a future time when Elastic Agent ingests from the Shodan API again.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Shodan**
3. Click on "Shodan" integration from the search results.
4. Click on **Add Shodan** button to add Webhooks integration.
5. Configure as appropriate

Example configuration,

![Integration Configuration](./img/shodan-integration-configuration.png)

### Configure the Shodan integration

#### Shodan API Key

An API key is created by default, and will be available on your [account page](https://account.shodan.io/).

Example,

![Shodan Account Page](./img/shodan-account-page.png)

You'll need to input this in the integration configuration, if you want to use the Host Search input.

#### Shodan Monitor Configuration

If you want to use this integration to receive Shodan Monitor notifications you will need to configure Shodan Monitor to send these to your integration's HTTP input.

How you plumb an Internet accessible HTTP or HTTPS service thru to your Elastic Agent input in order to receive webhook notifications is up to you.

CloudFlare Argo Tunneling and Load Balancing, or other Reverse Proxy style services are usually the best way in which to achieve this.

The official Shodan documentation regarding the Monitor service is available [here](https://help.shodan.io/developer-fundamentals/monitor-webhooks)

1. Navigate to [Shodan Monitor](https://monitor.shodan.io) and login if necessary
2. Click on "Settings"
3. Select "Webhook" from the drop down list, then click "ADD" next to it
4. Enter the URL to the Elastic Agent integration, e.g. **https://your.webhook.listener:8443/webhook**
5. Add a short description
6. Optionally select "Apply to existing alerts" if you want webhooks sent to Elastic for every asset monitor you already have
7. Optionally click "TEST" to confirm that Shodan can deliver webhooks to your Elastic Agent integrations
8. Click "Add Notifier"
9. For any future asset monitors that should trigger webhooks to Elastic, ensure you enable your webhook notification service as a destination

Example configuration process.

![Shodan Monitor Settings 1](./img/shodan-monitor-settings-1.png)

You should now have a webhook notification service available.

![Shodan Monitor Settings 2](./img/shodan-monitor-settings-2.png)

Optionally tick "Apply to existing alerts" if you want this webhook immediately added to all asset monitors that are already defined.

![Shodan Monitor Settings 3](./img/shodan-monitor-settings-3.png)

On each monitoring configuration you will be able to select the webhook as a notification service for alerts related to the network/assets found in the network.

![Shodan Monitor Settings 4](./img/shodan-monitor-settings-4.png)

## Shodan Host

Enable to collect Shodan host information via API host search, as well as host info received from Shodan Monitor sent as webhook events.

## Data Streams

### host

The `shodan.host` dataset stores events Shodan host information via API host search, as well as host info received from Shodan Monitor sent as webhook events.

All Shodan host event fields are available under the `shodan.host` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original |  | text |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| headers.\* |  | keyword |
| host.ip | Host ip addresses. | ip |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.body.content.text | Multi-field of `http.request.body.content`. | match_only_text |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.headers.\* |  | keyword |
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.version | HTTP version. | keyword |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | unsigned_long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| server.as.organization.name | Organization name. | keyword |
| server.as.organization.name.text | Multi-field of `server.as.organization.name`. | match_only_text |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.geo.city_name | City name. | keyword |
| server.geo.continent_name | Name of the continent. | keyword |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.geo.country_name | Country name. | keyword |
| server.geo.location | Longitude and latitude. | geo_point |
| server.geo.region_iso_code | Region ISO code. | keyword |
| server.geo.region_name | Region name. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| shodan.alert.id | Unique ID for the alert, as received via Shodan-Alert-ID HTTP header | keyword |
| shodan.alert.name | Name for the alert, as received via Shodan-Alert-ID HTTP header | keyword |
| shodan.alert.signature_sha1 | Trigger that caused the notification to get sent, as received via Shodan-Alert-Trigger HTTP header | keyword |
| shodan.alert.trigger | SHA1 signature encoded using your API key to validate the notification's origin, as received via Shodan-Signature-SHA1 HTTP header | keyword |
| shodan.host._shodan.crawler |  | keyword |
| shodan.host._shodan.id |  | keyword |
| shodan.host._shodan.module |  | keyword |
| shodan.host._shodan.options.hostname |  | keyword |
| shodan.host._shodan.options.referrer |  | keyword |
| shodan.host._shodan.options.scan |  | keyword |
| shodan.host._shodan.options.xrun |  | keyword |
| shodan.host._shodan.ptr |  | boolean |
| shodan.host._shodan.region |  | keyword |
| shodan.host.afp.afp_versions |  | keyword |
| shodan.host.afp.directory_names |  | keyword |
| shodan.host.afp.machine_type |  | keyword |
| shodan.host.afp.network_addresses |  | keyword |
| shodan.host.afp.server_flags.\* |  | keyword |
| shodan.host.afp.server_name |  | keyword |
| shodan.host.afp.server_signature |  | keyword |
| shodan.host.afp.uams |  | keyword |
| shodan.host.afp.utf8_server_name |  | keyword |
| shodan.host.airplay.device_id |  | keyword |
| shodan.host.airplay.device_model |  | keyword |
| shodan.host.airplay.firmware_build |  | keyword |
| shodan.host.airplay.firmware_build_date |  | keyword |
| shodan.host.airplay.hardware_revision |  | keyword |
| shodan.host.airplay.mac_address |  | keyword |
| shodan.host.airplay.name |  | keyword |
| shodan.host.airplay.os_build_version |  | keyword |
| shodan.host.airplay.protocol_version |  | keyword |
| shodan.host.airplay.sdk |  | keyword |
| shodan.host.airplay.vodka_version |  | keyword |
| shodan.host.amqp.locales |  | keyword |
| shodan.host.amqp.mechanisms |  | keyword |
| shodan.host.amqp.protocol_version |  | keyword |
| shodan.host.amqp.sasl_mechanisms |  | keyword |
| shodan.host.amqp.server_fields.capabilities.\* |  | keyword |
| shodan.host.amqp.server_fields.cluster_name |  | keyword |
| shodan.host.amqp.server_fields.copyright |  | keyword |
| shodan.host.amqp.server_fields.information |  | keyword |
| shodan.host.amqp.server_fields.platform |  | keyword |
| shodan.host.amqp.server_fields.product |  | keyword |
| shodan.host.amqp.server_fields.version |  | keyword |
| shodan.host.amqp.version_major |  | keyword |
| shodan.host.amqp.version_minor |  | keyword |
| shodan.host.asn |  | keyword |
| shodan.host.bacnet.appsoft |  | keyword |
| shodan.host.bacnet.desc |  | keyword |
| shodan.host.bacnet.fdt.ip |  | keyword |
| shodan.host.bacnet.fdt.port |  | keyword |
| shodan.host.bacnet.fdt.timeout |  | keyword |
| shodan.host.bacnet.fdt.ttl |  | keyword |
| shodan.host.bacnet.firmware |  | keyword |
| shodan.host.bacnet.instance_id |  | keyword |
| shodan.host.bacnet.location |  | keyword |
| shodan.host.bacnet.model |  | keyword |
| shodan.host.bacnet.name |  | keyword |
| shodan.host.bacnet.object |  | keyword |
| shodan.host.bgp.messages.asn |  | keyword |
| shodan.host.bgp.messages.bgp_identifier |  | keyword |
| shodan.host.bgp.messages.error_code |  | keyword |
| shodan.host.bgp.messages.error_subcode |  | keyword |
| shodan.host.bgp.messages.hold_time |  | keyword |
| shodan.host.bgp.messages.length |  | keyword |
| shodan.host.bgp.messages.type |  | keyword |
| shodan.host.bgp.messages.version |  | keyword |
| shodan.host.checkpoint.firewall_host |  | keyword |
| shodan.host.checkpoint.smartcenter_host |  | keyword |
| shodan.host.clickhouse.required_login |  | keyword |
| shodan.host.cloud.provider |  | keyword |
| shodan.host.cloud.region |  | keyword |
| shodan.host.cloud.service |  | keyword |
| shodan.host.coap.resources.\*.rt |  | keyword |
| shodan.host.cobalt_strike_beacon.\*.\* |  | keyword |
| shodan.host.consul.Datacenter |  | keyword |
| shodan.host.consul.NodeID |  | keyword |
| shodan.host.consul.NodeName |  | keyword |
| shodan.host.consul.PrimaryDatacenter |  | keyword |
| shodan.host.consul.Revision |  | keyword |
| shodan.host.consul.Server |  | keyword |
| shodan.host.consul.Version |  | keyword |
| shodan.host.couchdb.couchdb |  | keyword |
| shodan.host.couchdb.dbs |  | keyword |
| shodan.host.couchdb.features |  | keyword |
| shodan.host.couchdb.git_sha |  | keyword |
| shodan.host.couchdb.http_headers |  | keyword |
| shodan.host.couchdb.uuid |  | keyword |
| shodan.host.couchdb.vendor.name |  | keyword |
| shodan.host.couchdb.version |  | keyword |
| shodan.host.cpe |  | keyword |
| shodan.host.cpe23 |  | keyword |
| shodan.host.dahua.serial_number |  | keyword |
| shodan.host.dahua_dvr_web.channel_names |  | keyword |
| shodan.host.dahua_dvr_web.plugin.classid |  | keyword |
| shodan.host.dahua_dvr_web.plugin.mac_version |  | keyword |
| shodan.host.dahua_dvr_web.plugin.name |  | keyword |
| shodan.host.dahua_dvr_web.plugin.version |  | keyword |
| shodan.host.dahua_dvr_web.web_version |  | keyword |
| shodan.host.data |  | text |
| shodan.host.dav.allowed_methods |  | keyword |
| shodan.host.dav.paths |  | keyword |
| shodan.host.dav.public_options |  | keyword |
| shodan.host.dav.server_date |  | keyword |
| shodan.host.dav.server_type |  | keyword |
| shodan.host.dav.webdav_type |  | keyword |
| shodan.host.device |  | keyword |
| shodan.host.devicetype |  | keyword |
| shodan.host.dns.recursive |  | boolean |
| shodan.host.dns.resolver_hostname |  | keyword |
| shodan.host.dns.resolver_id |  | keyword |
| shodan.host.dns.software |  | keyword |
| shodan.host.docker_registry.error |  | keyword |
| shodan.host.docker_registry.repositories |  | keyword |
| shodan.host.domains |  | keyword |
| shodan.host.domoticz.build_time |  | keyword |
| shodan.host.domoticz.dzvents_version |  | keyword |
| shodan.host.domoticz.hash |  | keyword |
| shodan.host.domoticz.python_version |  | keyword |
| shodan.host.draytek_vigor.build_time |  | keyword |
| shodan.host.elastic.cluster._nodes.failed |  | keyword |
| shodan.host.elastic.cluster._nodes.successful |  | keyword |
| shodan.host.elastic.cluster._nodes.total |  | keyword |
| shodan.host.elastic.cluster.cluster_name |  | keyword |
| shodan.host.elastic.cluster.cluster_uuid |  | keyword |
| shodan.host.elastic.cluster.indices.analysis.\*.count |  | keyword |
| shodan.host.elastic.cluster.indices.analysis.\*.index_count |  | keyword |
| shodan.host.elastic.cluster.indices.analysis.\*.name |  | keyword |
| shodan.host.elastic.cluster.indices.completion.size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.count |  | keyword |
| shodan.host.elastic.cluster.indices.docs.count |  | keyword |
| shodan.host.elastic.cluster.indices.docs.deleted |  | keyword |
| shodan.host.elastic.cluster.indices.fielddata.evictions |  | keyword |
| shodan.host.elastic.cluster.indices.fielddata.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.filter_cache.evictions |  | keyword |
| shodan.host.elastic.cluster.indices.filter_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.id_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.field_types.count |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.field_types.index_count |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.field_types.name |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.field_types.script_count |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.total_deduplicated_field_count |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.total_deduplicated_mapping_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.mappings.total_field_count |  | keyword |
| shodan.host.elastic.cluster.indices.percolate.current |  | keyword |
| shodan.host.elastic.cluster.indices.percolate.memory_size |  | keyword |
| shodan.host.elastic.cluster.indices.percolate.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.percolate.queries |  | keyword |
| shodan.host.elastic.cluster.indices.percolate.time_in_millis |  | keyword |
| shodan.host.elastic.cluster.indices.percolate.total |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.cache_count |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.cache_size |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.evictions |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.hit_count |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.miss_count |  | keyword |
| shodan.host.elastic.cluster.indices.query_cache.total_count |  | keyword |
| shodan.host.elastic.cluster.indices.segments.count |  | keyword |
| shodan.host.elastic.cluster.indices.segments.doc_values_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.fixed_bit_set_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.index_writer_max_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.index_writer_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.max_unsafe_auto_id_timestamp |  | keyword |
| shodan.host.elastic.cluster.indices.segments.memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.norms_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.points_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.stored_fields_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.term_vectors_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.terms_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.segments.version_map_memory_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.primaries.avg |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.primaries.max |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.primaries.min |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.replication.avg |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.replication.max |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.replication.min |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.shards.avg |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.shards.max |  | keyword |
| shodan.host.elastic.cluster.indices.shards.index.shards.min |  | keyword |
| shodan.host.elastic.cluster.indices.shards.primaries |  | keyword |
| shodan.host.elastic.cluster.indices.shards.replication |  | keyword |
| shodan.host.elastic.cluster.indices.shards.total |  | keyword |
| shodan.host.elastic.cluster.indices.store.reserved_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.store.size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.store.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.cluster.indices.store.total_data_set_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.versions.index_count |  | keyword |
| shodan.host.elastic.cluster.indices.versions.primary_shard_count |  | keyword |
| shodan.host.elastic.cluster.indices.versions.total_primary_bytes |  | keyword |
| shodan.host.elastic.cluster.indices.versions.version |  | keyword |
| shodan.host.elastic.cluster.nodes.count.client |  | keyword |
| shodan.host.elastic.cluster.nodes.count.cluster_manager |  | keyword |
| shodan.host.elastic.cluster.nodes.count.coordinating_only |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data_cold |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data_content |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data_frozen |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data_hot |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data_only |  | keyword |
| shodan.host.elastic.cluster.nodes.count.data_warm |  | keyword |
| shodan.host.elastic.cluster.nodes.count.ingest |  | keyword |
| shodan.host.elastic.cluster.nodes.count.master |  | keyword |
| shodan.host.elastic.cluster.nodes.count.master_data |  | keyword |
| shodan.host.elastic.cluster.nodes.count.master_only |  | keyword |
| shodan.host.elastic.cluster.nodes.count.ml |  | keyword |
| shodan.host.elastic.cluster.nodes.count.remote_cluster_client |  | keyword |
| shodan.host.elastic.cluster.nodes.count.total |  | keyword |
| shodan.host.elastic.cluster.nodes.count.transform |  | keyword |
| shodan.host.elastic.cluster.nodes.count.voting_only |  | keyword |
| shodan.host.elastic.cluster.nodes.discovery_types.single-node |  | keyword |
| shodan.host.elastic.cluster.nodes.discovery_types.zen |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.available_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_io_op |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_io_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_queue |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_read_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_reads |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_service_time |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_write_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.disk_writes |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.free_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.spins |  | keyword |
| shodan.host.elastic.cluster.nodes.fs.total_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.current.all_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.current.combined_coordinating_and_primary_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.current.coordinating_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.current.primary_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.current.replica_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.limit_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.all_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.combined_coordinating_and_primary_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.coordinating_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.coordinating_rejections |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.primary_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.primary_rejections |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.replica_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.indexing_pressure.memory.total.replica_rejections |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.number_of_pipelines |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.gsub.count |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.gsub.current |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.gsub.failed |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.gsub.time_in_millis |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.script.count |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.script.current |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.script.failed |  | keyword |
| shodan.host.elastic.cluster.nodes.ingest.processor_stats.script.time_in_millis |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.max_uptime_in_millis |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.mem.heap_max_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.mem.heap_used_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.threads |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.bundled_jdk |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.count |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.using_bundled_jdk |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.version |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.vm_name |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.vm_vendor |  | keyword |
| shodan.host.elastic.cluster.nodes.jvm.versions.vm_version |  | keyword |
| shodan.host.elastic.cluster.nodes.network_types.http_types.filter-jetty |  | keyword |
| shodan.host.elastic.cluster.nodes.network_types.http_types.netty4 |  | keyword |
| shodan.host.elastic.cluster.nodes.network_types.http_types.security4 |  | keyword |
| shodan.host.elastic.cluster.nodes.network_types.transport_types.netty4 |  | keyword |
| shodan.host.elastic.cluster.nodes.network_types.transport_types.org_opensearch_security_ssl_http_netty_SecuritySSLNettyTransport |  | keyword |
| shodan.host.elastic.cluster.nodes.network_types.transport_types.security4 |  | keyword |
| shodan.host.elastic.cluster.nodes.os.allocated_processors |  | keyword |
| shodan.host.elastic.cluster.nodes.os.architectures.arch |  | keyword |
| shodan.host.elastic.cluster.nodes.os.architectures.count |  | keyword |
| shodan.host.elastic.cluster.nodes.os.available_processors |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.cache_size_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.cores_per_socket |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.count |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.mhz |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.model |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.total_cores |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.total_sockets |  | keyword |
| shodan.host.elastic.cluster.nodes.os.cpu.vendor |  | keyword |
| shodan.host.elastic.cluster.nodes.os.mem.adjusted_total_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.os.mem.free_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.os.mem.free_percent |  | keyword |
| shodan.host.elastic.cluster.nodes.os.mem.total_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.os.mem.used_in_bytes |  | keyword |
| shodan.host.elastic.cluster.nodes.os.mem.used_percent |  | keyword |
| shodan.host.elastic.cluster.nodes.os.names.count |  | keyword |
| shodan.host.elastic.cluster.nodes.os.names.name |  | keyword |
| shodan.host.elastic.cluster.nodes.os.pretty_names.count |  | keyword |
| shodan.host.elastic.cluster.nodes.os.pretty_names.pretty_name |  | keyword |
| shodan.host.elastic.cluster.nodes.packaging_types.count |  | keyword |
| shodan.host.elastic.cluster.nodes.packaging_types.flavor |  | keyword |
| shodan.host.elastic.cluster.nodes.packaging_types.type |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.classname |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.description |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.elasticsearch_version |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.extended_plugins |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.has_native_controller |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.java_version |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.jvm |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.licensed |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.name |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.requires_keystore |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.site |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.type |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.url |  | keyword |
| shodan.host.elastic.cluster.nodes.plugins.version |  | keyword |
| shodan.host.elastic.cluster.nodes.process.cpu.percent |  | keyword |
| shodan.host.elastic.cluster.nodes.process.open_file_descriptors.avg |  | keyword |
| shodan.host.elastic.cluster.nodes.process.open_file_descriptors.max |  | keyword |
| shodan.host.elastic.cluster.nodes.process.open_file_descriptors.min |  | keyword |
| shodan.host.elastic.cluster.nodes.versions |  | keyword |
| shodan.host.elastic.cluster.status |  | keyword |
| shodan.host.elastic.cluster.timestamp |  | keyword |
| shodan.host.elastic.indices.\*.primaries.completion.size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.docs.count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.docs.deleted |  | keyword |
| shodan.host.elastic.indices.\*.primaries.fielddata.evictions |  | keyword |
| shodan.host.elastic.indices.\*.primaries.fielddata.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.flush.periodic |  | keyword |
| shodan.host.elastic.indices.\*.primaries.flush.total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.flush.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.exists_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.exists_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.missing_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.missing_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.get.total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.delete_current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.delete_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.delete_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.index_current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.index_failed |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.index_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.index_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.is_throttled |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.noop_update_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.indexing.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.current_docs |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.current_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total_auto_throttle_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total_docs |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total_stopped_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total_throttled_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.merges.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.cache_count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.cache_size |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.evictions |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.hit_count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.miss_count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.query_cache.total_count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.recovery.current_as_source |  | keyword |
| shodan.host.elastic.indices.\*.primaries.recovery.current_as_target |  | keyword |
| shodan.host.elastic.indices.\*.primaries.recovery.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.refresh.external_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.refresh.external_total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.refresh.listeners |  | keyword |
| shodan.host.elastic.indices.\*.primaries.refresh.total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.refresh.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.request_cache.evictions |  | keyword |
| shodan.host.elastic.indices.\*.primaries.request_cache.hit_count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.request_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.request_cache.miss_count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.fetch_current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.fetch_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.fetch_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.open_contexts |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.query_current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.query_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.query_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.scroll_current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.scroll_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.scroll_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.suggest_current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.suggest_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.primaries.search.suggest_total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.count |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.doc_values_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.fixed_bit_set_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.index_writer_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.max_unsafe_auto_id_timestamp |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.norms_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.points_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.stored_fields_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.term_vectors_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.terms_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.segments.version_map_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.store.size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.translog.earliest_last_modified_age |  | keyword |
| shodan.host.elastic.indices.\*.primaries.translog.operations |  | keyword |
| shodan.host.elastic.indices.\*.primaries.translog.size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.translog.uncommitted_operations |  | keyword |
| shodan.host.elastic.indices.\*.primaries.translog.uncommitted_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.primaries.warmer.current |  | keyword |
| shodan.host.elastic.indices.\*.primaries.warmer.total |  | keyword |
| shodan.host.elastic.indices.\*.primaries.warmer.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.completion.size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.docs.count |  | keyword |
| shodan.host.elastic.indices.\*.total.docs.deleted |  | keyword |
| shodan.host.elastic.indices.\*.total.fielddata.evictions |  | keyword |
| shodan.host.elastic.indices.\*.total.fielddata.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.flush.periodic |  | keyword |
| shodan.host.elastic.indices.\*.total.flush.total |  | keyword |
| shodan.host.elastic.indices.\*.total.flush.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.get.current |  | keyword |
| shodan.host.elastic.indices.\*.total.get.exists_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.get.exists_total |  | keyword |
| shodan.host.elastic.indices.\*.total.get.missing_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.get.missing_total |  | keyword |
| shodan.host.elastic.indices.\*.total.get.time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.get.total |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.delete_current |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.delete_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.delete_total |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.index_current |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.index_failed |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.index_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.index_total |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.is_throttled |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.noop_update_total |  | keyword |
| shodan.host.elastic.indices.\*.total.indexing.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.current |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.current_docs |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.current_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total_auto_throttle_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total_docs |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total_stopped_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total_throttled_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.merges.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.cache_count |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.cache_size |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.evictions |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.hit_count |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.miss_count |  | keyword |
| shodan.host.elastic.indices.\*.total.query_cache.total_count |  | keyword |
| shodan.host.elastic.indices.\*.total.recovery.current_as_source |  | keyword |
| shodan.host.elastic.indices.\*.total.recovery.current_as_target |  | keyword |
| shodan.host.elastic.indices.\*.total.recovery.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.refresh.external_total |  | keyword |
| shodan.host.elastic.indices.\*.total.refresh.external_total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.refresh.listeners |  | keyword |
| shodan.host.elastic.indices.\*.total.refresh.total |  | keyword |
| shodan.host.elastic.indices.\*.total.refresh.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.request_cache.evictions |  | keyword |
| shodan.host.elastic.indices.\*.total.request_cache.hit_count |  | keyword |
| shodan.host.elastic.indices.\*.total.request_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.request_cache.miss_count |  | keyword |
| shodan.host.elastic.indices.\*.total.search.fetch_current |  | keyword |
| shodan.host.elastic.indices.\*.total.search.fetch_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.search.fetch_total |  | keyword |
| shodan.host.elastic.indices.\*.total.search.open_contexts |  | keyword |
| shodan.host.elastic.indices.\*.total.search.query_current |  | keyword |
| shodan.host.elastic.indices.\*.total.search.query_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.search.query_total |  | keyword |
| shodan.host.elastic.indices.\*.total.search.scroll_current |  | keyword |
| shodan.host.elastic.indices.\*.total.search.scroll_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.search.scroll_total |  | keyword |
| shodan.host.elastic.indices.\*.total.search.suggest_current |  | keyword |
| shodan.host.elastic.indices.\*.total.search.suggest_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.total.search.suggest_total |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.count |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.doc_values_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.fixed_bit_set_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.index_writer_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.max_unsafe_auto_id_timestamp |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.norms_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.points_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.stored_fields_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.term_vectors_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.terms_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.segments.version_map_memory_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.store.size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.translog.earliest_last_modified_age |  | keyword |
| shodan.host.elastic.indices.\*.total.translog.operations |  | keyword |
| shodan.host.elastic.indices.\*.total.translog.size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.translog.uncommitted_operations |  | keyword |
| shodan.host.elastic.indices.\*.total.translog.uncommitted_size_in_bytes |  | keyword |
| shodan.host.elastic.indices.\*.total.warmer.current |  | keyword |
| shodan.host.elastic.indices.\*.total.warmer.total |  | keyword |
| shodan.host.elastic.indices.\*.total.warmer.total_time_in_millis |  | keyword |
| shodan.host.elastic.indices.\*.uuid |  | keyword |
| shodan.host.elastic.nodes._nodes.failed |  | keyword |
| shodan.host.elastic.nodes._nodes.successful |  | keyword |
| shodan.host.elastic.nodes._nodes.total |  | keyword |
| shodan.host.elastic.nodes.cluster_name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.attributes.ml_enabled |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.attributes.ml_machine_memory |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.attributes.ml_max_open_jobs |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.build_hash |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.host |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.http.bound_address |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.http.max_content_length_in_bytes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.http.publish_address |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.ingest.processors.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.ip |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.gc_collectors |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.input_arguments |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.mem.direct_max_in_bytes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.mem.heap_init_in_bytes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.mem.heap_max_in_bytes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.mem.non_heap_init_in_bytes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.mem.non_heap_max_in_bytes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.memory_pools |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.pid |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.start_time_in_millis |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.using_compressed_ordinary_object_pointers |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.version |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.vm_name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.vm_vendor |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.jvm.vm_version |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.modules.classname |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.modules.description |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.modules.has_native_controller |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.modules.name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.modules.requires_keystore |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.modules.version |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.os.allocated_processors |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.os.arch |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.os.available_processors |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.os.name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.os.refresh_interval_in_millis |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.os.version |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.classname |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.description |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.extended_plugins |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.has_native_controller |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.requires_keystore |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.plugins.version |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.process.id |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.process.mlockall |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.process.refresh_interval_in_millis |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.roles |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.bootstrap.memory_lock |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.client.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.cluster.name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.discovery.zen.minimum_master_nodes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.discovery.zen.ping.unicast.hosts |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.http.type.default |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.network.host |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.attr.ml.enabled |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.attr.ml.machine_memory |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.attr.ml.max_open_jobs |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.data |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.master |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.max_local_storage_nodes |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.node.name |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.path.data |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.path.home |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.path.logs |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.pidfile |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.transport.type.default |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.settings.xpack.security.enabled |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.bulk.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.bulk.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.bulk.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.bulk.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_started.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_started.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_started.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_started.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_started.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_store.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_store.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_store.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_store.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.fetch_shard_store.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.flush.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.flush.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.flush.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.flush.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.flush.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.force_merge.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.force_merge.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.force_merge.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.force_merge.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.generic.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.generic.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.generic.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.generic.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.generic.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.get.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.get.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.get.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.get.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.index.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.index.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.index.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.index.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.listener.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.listener.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.listener.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.listener.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.management.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.management.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.management.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.management.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.management.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_autodetect.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_autodetect.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_autodetect.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_autodetect.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_datafeed.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_datafeed.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_datafeed.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_datafeed.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_utility.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_utility.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_utility.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.ml_utility.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.refresh.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.refresh.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.refresh.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.refresh.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.refresh.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.search.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.search.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.search.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.search.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.snapshot.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.snapshot.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.snapshot.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.snapshot.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.snapshot.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.warmer.keep_alive |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.warmer.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.warmer.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.warmer.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.warmer.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.watcher.max |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.watcher.min |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.watcher.queue_size |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.thread_pool.watcher.type |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.total_indexing_buffer |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.transport.bound_address |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.transport.publish_address |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.transport_address |  | keyword |
| shodan.host.elastic.nodes.nodes.\*.version |  | keyword |
| shodan.host.elastic.total.completion.size_in_bytes |  | keyword |
| shodan.host.elastic.total.docs.count |  | keyword |
| shodan.host.elastic.total.docs.deleted |  | keyword |
| shodan.host.elastic.total.fielddata.evictions |  | keyword |
| shodan.host.elastic.total.fielddata.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.total.flush.periodic |  | keyword |
| shodan.host.elastic.total.flush.total |  | keyword |
| shodan.host.elastic.total.flush.total_time_in_millis |  | keyword |
| shodan.host.elastic.total.get.current |  | keyword |
| shodan.host.elastic.total.get.exists_time_in_millis |  | keyword |
| shodan.host.elastic.total.get.exists_total |  | keyword |
| shodan.host.elastic.total.get.missing_time_in_millis |  | keyword |
| shodan.host.elastic.total.get.missing_total |  | keyword |
| shodan.host.elastic.total.get.time_in_millis |  | keyword |
| shodan.host.elastic.total.get.total |  | keyword |
| shodan.host.elastic.total.indexing.delete_current |  | keyword |
| shodan.host.elastic.total.indexing.delete_time_in_millis |  | keyword |
| shodan.host.elastic.total.indexing.delete_total |  | keyword |
| shodan.host.elastic.total.indexing.index_current |  | keyword |
| shodan.host.elastic.total.indexing.index_failed |  | keyword |
| shodan.host.elastic.total.indexing.index_time_in_millis |  | keyword |
| shodan.host.elastic.total.indexing.index_total |  | keyword |
| shodan.host.elastic.total.indexing.is_throttled |  | keyword |
| shodan.host.elastic.total.indexing.noop_update_total |  | keyword |
| shodan.host.elastic.total.indexing.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.total.merges.current |  | keyword |
| shodan.host.elastic.total.merges.current_docs |  | keyword |
| shodan.host.elastic.total.merges.current_size_in_bytes |  | keyword |
| shodan.host.elastic.total.merges.total |  | keyword |
| shodan.host.elastic.total.merges.total_auto_throttle_in_bytes |  | keyword |
| shodan.host.elastic.total.merges.total_docs |  | keyword |
| shodan.host.elastic.total.merges.total_size_in_bytes |  | keyword |
| shodan.host.elastic.total.merges.total_stopped_time_in_millis |  | keyword |
| shodan.host.elastic.total.merges.total_throttled_time_in_millis |  | keyword |
| shodan.host.elastic.total.merges.total_time_in_millis |  | keyword |
| shodan.host.elastic.total.query_cache.cache_count |  | keyword |
| shodan.host.elastic.total.query_cache.cache_size |  | keyword |
| shodan.host.elastic.total.query_cache.evictions |  | keyword |
| shodan.host.elastic.total.query_cache.hit_count |  | keyword |
| shodan.host.elastic.total.query_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.total.query_cache.miss_count |  | keyword |
| shodan.host.elastic.total.query_cache.total_count |  | keyword |
| shodan.host.elastic.total.recovery.current_as_source |  | keyword |
| shodan.host.elastic.total.recovery.current_as_target |  | keyword |
| shodan.host.elastic.total.recovery.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.total.refresh.external_total |  | keyword |
| shodan.host.elastic.total.refresh.external_total_time_in_millis |  | keyword |
| shodan.host.elastic.total.refresh.listeners |  | keyword |
| shodan.host.elastic.total.refresh.total |  | keyword |
| shodan.host.elastic.total.refresh.total_time_in_millis |  | keyword |
| shodan.host.elastic.total.request_cache.evictions |  | keyword |
| shodan.host.elastic.total.request_cache.hit_count |  | keyword |
| shodan.host.elastic.total.request_cache.memory_size_in_bytes |  | keyword |
| shodan.host.elastic.total.request_cache.miss_count |  | keyword |
| shodan.host.elastic.total.search.fetch_current |  | keyword |
| shodan.host.elastic.total.search.fetch_time_in_millis |  | keyword |
| shodan.host.elastic.total.search.fetch_total |  | keyword |
| shodan.host.elastic.total.search.open_contexts |  | keyword |
| shodan.host.elastic.total.search.query_current |  | keyword |
| shodan.host.elastic.total.search.query_time_in_millis |  | keyword |
| shodan.host.elastic.total.search.query_total |  | keyword |
| shodan.host.elastic.total.search.scroll_current |  | keyword |
| shodan.host.elastic.total.search.scroll_time_in_millis |  | keyword |
| shodan.host.elastic.total.search.scroll_total |  | keyword |
| shodan.host.elastic.total.search.suggest_current |  | keyword |
| shodan.host.elastic.total.search.suggest_time_in_millis |  | keyword |
| shodan.host.elastic.total.search.suggest_total |  | keyword |
| shodan.host.elastic.total.segments.count |  | keyword |
| shodan.host.elastic.total.segments.doc_values_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.fixed_bit_set_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.index_writer_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.max_unsafe_auto_id_timestamp |  | keyword |
| shodan.host.elastic.total.segments.memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.norms_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.points_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.stored_fields_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.term_vectors_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.terms_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.segments.version_map_memory_in_bytes |  | keyword |
| shodan.host.elastic.total.store.reserved_in_bytes |  | keyword |
| shodan.host.elastic.total.store.size_in_bytes |  | keyword |
| shodan.host.elastic.total.store.throttle_time_in_millis |  | keyword |
| shodan.host.elastic.total.store.total_data_set_size_in_bytes |  | keyword |
| shodan.host.elastic.total.translog.earliest_last_modified_age |  | keyword |
| shodan.host.elastic.total.translog.operations |  | keyword |
| shodan.host.elastic.total.translog.size_in_bytes |  | keyword |
| shodan.host.elastic.total.translog.uncommitted_operations |  | keyword |
| shodan.host.elastic.total.translog.uncommitted_size_in_bytes |  | keyword |
| shodan.host.elastic.total.warmer.current |  | keyword |
| shodan.host.elastic.total.warmer.total |  | keyword |
| shodan.host.elastic.total.warmer.total_time_in_millis |  | keyword |
| shodan.host.epmd.nodes.bigcouch |  | keyword |
| shodan.host.epmd.nodes.ecallmgr |  | keyword |
| shodan.host.epmd.nodes.freeswitch |  | keyword |
| shodan.host.epmd.nodes.gateway_config |  | keyword |
| shodan.host.epmd.nodes.kazoo-rabbitmq |  | keyword |
| shodan.host.epmd.nodes.kazoo_apps |  | keyword |
| shodan.host.epmd.nodes.kolab_guam |  | keyword |
| shodan.host.epmd.nodes.nisystemlink |  | keyword |
| shodan.host.epmd.nodes.rabbit |  | keyword |
| shodan.host.epmd.nodes.vpnu-radius |  | keyword |
| shodan.host.ethereum_p2p.neighbors.ip |  | keyword |
| shodan.host.ethereum_p2p.neighbors.pubkey |  | keyword |
| shodan.host.ethereum_p2p.neighbors.tcp_port |  | keyword |
| shodan.host.ethereum_p2p.neighbors.udp_port |  | keyword |
| shodan.host.ethereum_p2p.pubkey |  | keyword |
| shodan.host.ethereum_p2p.tcp_port |  | keyword |
| shodan.host.ethereum_p2p.udp_port |  | keyword |
| shodan.host.ethereum_rpc.accounts |  | keyword |
| shodan.host.ethereum_rpc.chain_id |  | keyword |
| shodan.host.ethereum_rpc.client |  | keyword |
| shodan.host.ethereum_rpc.compiler |  | keyword |
| shodan.host.ethereum_rpc.hashrate |  | keyword |
| shodan.host.ethereum_rpc.platform |  | keyword |
| shodan.host.ethereum_rpc.version |  | keyword |
| shodan.host.ethernetip.command |  | keyword |
| shodan.host.ethernetip.command_length |  | keyword |
| shodan.host.ethernetip.command_status |  | keyword |
| shodan.host.ethernetip.device_type |  | keyword |
| shodan.host.ethernetip.encapsulation_length |  | keyword |
| shodan.host.ethernetip.ip |  | keyword |
| shodan.host.ethernetip.item_count |  | keyword |
| shodan.host.ethernetip.options |  | keyword |
| shodan.host.ethernetip.product_code |  | keyword |
| shodan.host.ethernetip.product_name |  | keyword |
| shodan.host.ethernetip.product_name_length |  | keyword |
| shodan.host.ethernetip.raw |  | text |
| shodan.host.ethernetip.revision_major |  | keyword |
| shodan.host.ethernetip.revision_minor |  | keyword |
| shodan.host.ethernetip.sender_context |  | keyword |
| shodan.host.ethernetip.serial |  | keyword |
| shodan.host.ethernetip.session |  | keyword |
| shodan.host.ethernetip.socket_addr |  | keyword |
| shodan.host.ethernetip.state |  | keyword |
| shodan.host.ethernetip.status |  | keyword |
| shodan.host.ethernetip.type_id |  | keyword |
| shodan.host.ethernetip.vendor_id |  | keyword |
| shodan.host.ethernetip.version |  | keyword |
| shodan.host.fortinet.device |  | keyword |
| shodan.host.fortinet.model |  | keyword |
| shodan.host.fortinet.serial_number |  | keyword |
| shodan.host.ftp.anonymous |  | keyword |
| shodan.host.ftp.features.\*.parameters |  | keyword |
| shodan.host.ftp.features_hash |  | keyword |
| shodan.host.ganglia.clusters.name |  | keyword |
| shodan.host.ganglia.clusters.owner |  | keyword |
| shodan.host.ganglia.version |  | keyword |
| shodan.host.hash |  | keyword |
| shodan.host.hikvision.activex_files.\* |  | keyword |
| shodan.host.hikvision.custom_version |  | keyword |
| shodan.host.hikvision.device_model |  | keyword |
| shodan.host.hikvision.device_version |  | keyword |
| shodan.host.hikvision.plugin_version |  | keyword |
| shodan.host.hikvision.web_version |  | keyword |
| shodan.host.home_assistant.base_url |  | keyword |
| shodan.host.home_assistant.installation_type |  | keyword |
| shodan.host.home_assistant.internal_url |  | keyword |
| shodan.host.home_assistant.location_name |  | keyword |
| shodan.host.home_assistant.uuid |  | keyword |
| shodan.host.homebridge.enable_accessories |  | keyword |
| shodan.host.homebridge.enable_terminal_access |  | keyword |
| shodan.host.homebridge.instance_id |  | keyword |
| shodan.host.homebridge.instance_name |  | keyword |
| shodan.host.homebridge.node_version |  | keyword |
| shodan.host.homebridge.platform |  | keyword |
| shodan.host.homebridge.running_in_docker |  | keyword |
| shodan.host.homebridge.running_in_linux |  | keyword |
| shodan.host.homebridge.service_mode |  | keyword |
| shodan.host.homebridge.ui_package_name |  | keyword |
| shodan.host.homebridge.ui_package_version |  | keyword |
| shodan.host.hostnames |  | keyword |
| shodan.host.hp_ilo.cuuid |  | keyword |
| shodan.host.hp_ilo.ilo_firmware |  | keyword |
| shodan.host.hp_ilo.ilo_serial_number |  | keyword |
| shodan.host.hp_ilo.ilo_type |  | keyword |
| shodan.host.hp_ilo.ilo_uuid |  | keyword |
| shodan.host.hp_ilo.nics.description |  | keyword |
| shodan.host.hp_ilo.nics.ip_address |  | keyword |
| shodan.host.hp_ilo.nics.location |  | keyword |
| shodan.host.hp_ilo.nics.mac_address |  | keyword |
| shodan.host.hp_ilo.nics.port |  | keyword |
| shodan.host.hp_ilo.nics.status |  | keyword |
| shodan.host.hp_ilo.product_id |  | keyword |
| shodan.host.hp_ilo.serial_number |  | keyword |
| shodan.host.hp_ilo.server_type |  | keyword |
| shodan.host.hp_ilo.uuid |  | keyword |
| shodan.host.html |  | keyword |
| shodan.host.http.components.\*.categories |  | keyword |
| shodan.host.http.favicon.data |  | text |
| shodan.host.http.favicon.hash |  | keyword |
| shodan.host.http.favicon.location |  | keyword |
| shodan.host.http.headers_hash |  | keyword |
| shodan.host.http.host |  | keyword |
| shodan.host.http.html |  | text |
| shodan.host.http.html_hash |  | keyword |
| shodan.host.http.location |  | keyword |
| shodan.host.http.redirects.data |  | text |
| shodan.host.http.redirects.host |  | keyword |
| shodan.host.http.redirects.html |  | text |
| shodan.host.http.redirects.location |  | keyword |
| shodan.host.http.robots |  | text |
| shodan.host.http.robots_hash |  | keyword |
| shodan.host.http.securitytxt |  | text |
| shodan.host.http.securitytxt_hash |  | keyword |
| shodan.host.http.server |  | keyword |
| shodan.host.http.sitemap |  | text |
| shodan.host.http.sitemap_hash |  | keyword |
| shodan.host.http.status |  | keyword |
| shodan.host.http.title |  | keyword |
| shodan.host.http.waf |  | keyword |
| shodan.host.influxdb.bind_address |  | keyword |
| shodan.host.influxdb.build |  | keyword |
| shodan.host.influxdb.databases |  | keyword |
| shodan.host.influxdb.go_arch |  | keyword |
| shodan.host.influxdb.go_max_procs |  | keyword |
| shodan.host.influxdb.go_os |  | keyword |
| shodan.host.influxdb.go_version |  | keyword |
| shodan.host.influxdb.network_hostname |  | keyword |
| shodan.host.influxdb.uptime |  | keyword |
| shodan.host.influxdb.version |  | keyword |
| shodan.host.info |  | text |
| shodan.host.ip |  | keyword |
| shodan.host.ip_camera.alias_name |  | keyword |
| shodan.host.ip_camera.app_version |  | keyword |
| shodan.host.ip_camera.brand |  | keyword |
| shodan.host.ip_camera.build |  | keyword |
| shodan.host.ip_camera.ddns_host |  | keyword |
| shodan.host.ip_camera.hardware_version |  | keyword |
| shodan.host.ip_camera.id |  | keyword |
| shodan.host.ip_camera.ip_address |  | keyword |
| shodan.host.ip_camera.mac_address |  | keyword |
| shodan.host.ip_camera.model |  | keyword |
| shodan.host.ip_camera.name |  | keyword |
| shodan.host.ip_camera.product |  | keyword |
| shodan.host.ip_camera.system_version |  | keyword |
| shodan.host.ip_camera.version |  | keyword |
| shodan.host.ip_str |  | keyword |
| shodan.host.ipmi.level |  | keyword |
| shodan.host.ipmi.oemid |  | keyword |
| shodan.host.ipmi.password_auth |  | keyword |
| shodan.host.ipmi.user_auth |  | keyword |
| shodan.host.ipmi.version |  | keyword |
| shodan.host.ipp_cups.printers.location |  | keyword |
| shodan.host.ipp_cups.printers.make_and_model |  | keyword |
| shodan.host.ipp_cups.printers.name |  | keyword |
| shodan.host.ipp_cups.printers.uri_supported |  | keyword |
| shodan.host.ipp_cups.status_message |  | keyword |
| shodan.host.ipv6 |  | keyword |
| shodan.host.isakmp.aggressive.exchange_type |  | keyword |
| shodan.host.isakmp.aggressive.flags.authentication |  | keyword |
| shodan.host.isakmp.aggressive.flags.commit |  | keyword |
| shodan.host.isakmp.aggressive.flags.encryption |  | keyword |
| shodan.host.isakmp.aggressive.initiator_spi |  | keyword |
| shodan.host.isakmp.aggressive.length |  | keyword |
| shodan.host.isakmp.aggressive.msg_id |  | keyword |
| shodan.host.isakmp.aggressive.next_payload |  | keyword |
| shodan.host.isakmp.aggressive.responder_spi |  | keyword |
| shodan.host.isakmp.aggressive.version |  | keyword |
| shodan.host.isakmp.exchange_type |  | keyword |
| shodan.host.isakmp.flags.authentication |  | keyword |
| shodan.host.isakmp.flags.commit |  | keyword |
| shodan.host.isakmp.flags.encryption |  | keyword |
| shodan.host.isakmp.initiator_spi |  | keyword |
| shodan.host.isakmp.length |  | keyword |
| shodan.host.isakmp.msg_id |  | keyword |
| shodan.host.isakmp.next_payload |  | keyword |
| shodan.host.isakmp.responder_spi |  | keyword |
| shodan.host.isakmp.version |  | keyword |
| shodan.host.isp |  | keyword |
| shodan.host.kafka.brokers.id |  | keyword |
| shodan.host.kafka.brokers.name |  | keyword |
| shodan.host.kafka.brokers.port |  | keyword |
| shodan.host.kafka.hosts.name |  | keyword |
| shodan.host.kafka.hosts.port |  | keyword |
| shodan.host.kafka.topics |  | keyword |
| shodan.host.knx.device.friendly_name |  | keyword |
| shodan.host.knx.device.knx_address |  | keyword |
| shodan.host.knx.device.mac |  | keyword |
| shodan.host.knx.device.multicast_address |  | keyword |
| shodan.host.knx.device.serial |  | keyword |
| shodan.host.knx.supported_services.core |  | keyword |
| shodan.host.knx.supported_services.device_management |  | keyword |
| shodan.host.knx.supported_services.remote_config |  | keyword |
| shodan.host.knx.supported_services.routing |  | keyword |
| shodan.host.knx.supported_services.tunneling |  | keyword |
| shodan.host.kubernetes.build_date |  | keyword |
| shodan.host.kubernetes.go_version |  | keyword |
| shodan.host.kubernetes.platform |  | keyword |
| shodan.host.last_update |  | date |
| shodan.host.ldap.\* |  | keyword |
| shodan.host.location.area_code |  | keyword |
| shodan.host.location.city |  | keyword |
| shodan.host.location.country_code |  | keyword |
| shodan.host.location.country_code3 |  | keyword |
| shodan.host.location.country_name |  | keyword |
| shodan.host.location.dma_code |  | keyword |
| shodan.host.location.latitude |  | keyword |
| shodan.host.location.longitude |  | keyword |
| shodan.host.location.postal_code |  | keyword |
| shodan.host.location.raw |  | text |
| shodan.host.location.region_code |  | keyword |
| shodan.host.mac.\*.assignment |  | keyword |
| shodan.host.mac.\*.date |  | keyword |
| shodan.host.mac.\*.org |  | keyword |
| shodan.host.mdns.answers.\* |  | keyword |
| shodan.host.mdns.services.\*.data |  | text |
| shodan.host.mdns.services.\*.ipv4 |  | keyword |
| shodan.host.mdns.services.\*.ipv6 |  | keyword |
| shodan.host.mdns.services.\*.name |  | keyword |
| shodan.host.mdns.services.\*.port |  | keyword |
| shodan.host.mdns.services.\*.ptr |  | keyword |
| shodan.host.mikrotik_routeros.interfaces |  | keyword |
| shodan.host.mikrotik_routeros.version |  | keyword |
| shodan.host.mikrotik_winbox.index.\*.crc |  | keyword |
| shodan.host.mikrotik_winbox.index.\*.size |  | keyword |
| shodan.host.mikrotik_winbox.index.\*.version |  | keyword |
| shodan.host.mikrotik_winbox.list.\*.crc |  | keyword |
| shodan.host.mikrotik_winbox.list.\*.size |  | keyword |
| shodan.host.mikrotik_winbox.list.\*.version |  | keyword |
| shodan.host.minecraft.brand |  | keyword |
| shodan.host.minecraft.description |  | text |
| shodan.host.minecraft.enforcesSecureChat |  | keyword |
| shodan.host.minecraft.favicon |  | keyword |
| shodan.host.minecraft.forgeData.channels.required |  | keyword |
| shodan.host.minecraft.forgeData.channels.res |  | keyword |
| shodan.host.minecraft.forgeData.channels.version |  | keyword |
| shodan.host.minecraft.forgeData.d |  | keyword |
| shodan.host.minecraft.forgeData.fmlNetworkVersion |  | keyword |
| shodan.host.minecraft.forgeData.mods.modId |  | keyword |
| shodan.host.minecraft.forgeData.mods.modmarker |  | keyword |
| shodan.host.minecraft.forgeData.truncated |  | keyword |
| shodan.host.minecraft.gamemode |  | keyword |
| shodan.host.minecraft.map |  | keyword |
| shodan.host.minecraft.modinfo.modList.modid |  | keyword |
| shodan.host.minecraft.modinfo.modList.version |  | keyword |
| shodan.host.minecraft.modinfo.type |  | keyword |
| shodan.host.minecraft.modpackData.URLS.repository |  | keyword |
| shodan.host.minecraft.modpackData.URLS.support |  | keyword |
| shodan.host.minecraft.modpackData.URLS.website |  | keyword |
| shodan.host.minecraft.modpackData.enableTitlescreenBranding |  | keyword |
| shodan.host.minecraft.modpackData.enabled |  | keyword |
| shodan.host.minecraft.modpackData.isMetadata |  | keyword |
| shodan.host.minecraft.modpackData.modpackAuthors |  | keyword |
| shodan.host.minecraft.modpackData.modpackID |  | keyword |
| shodan.host.minecraft.modpackData.modpackName |  | keyword |
| shodan.host.minecraft.modpackData.modpackVersion.ID |  | keyword |
| shodan.host.minecraft.modpackData.modpackVersion.releaseType |  | keyword |
| shodan.host.minecraft.modpackData.modpackVersion.semName |  | keyword |
| shodan.host.minecraft.modpackData.name |  | keyword |
| shodan.host.minecraft.modpackData.projectID |  | keyword |
| shodan.host.minecraft.modpackData.releaseType |  | keyword |
| shodan.host.minecraft.modpackData.version |  | keyword |
| shodan.host.minecraft.modpackData.versionID |  | keyword |
| shodan.host.minecraft.players.max |  | keyword |
| shodan.host.minecraft.players.online |  | keyword |
| shodan.host.minecraft.players.sample.id |  | keyword |
| shodan.host.minecraft.players.sample.name |  | keyword |
| shodan.host.minecraft.preventsChatReports |  | keyword |
| shodan.host.minecraft.previewsChat |  | keyword |
| shodan.host.minecraft.version.name |  | keyword |
| shodan.host.minecraft.version.protocol |  | keyword |
| shodan.host.mongodb.authentication |  | keyword |
| shodan.host.mongodb.buildInfo.allocator |  | keyword |
| shodan.host.mongodb.buildInfo.bits |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.cc |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.ccflags |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.cppdefines |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.cxx |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.cxxflags |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.distarch |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.distmod |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.linkflags |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.target_arch |  | keyword |
| shodan.host.mongodb.buildInfo.buildEnvironment.target_os |  | keyword |
| shodan.host.mongodb.buildInfo.clusterTime.clusterTime |  | keyword |
| shodan.host.mongodb.buildInfo.clusterTime.signature.hash |  | keyword |
| shodan.host.mongodb.buildInfo.clusterTime.signature.keyId |  | keyword |
| shodan.host.mongodb.buildInfo.debug |  | keyword |
| shodan.host.mongodb.buildInfo.gitVersion |  | keyword |
| shodan.host.mongodb.buildInfo.javascriptEngine |  | keyword |
| shodan.host.mongodb.buildInfo.maxBsonObjectSize |  | keyword |
| shodan.host.mongodb.buildInfo.ok |  | keyword |
| shodan.host.mongodb.buildInfo.openssl.compiled |  | keyword |
| shodan.host.mongodb.buildInfo.openssl.running |  | keyword |
| shodan.host.mongodb.buildInfo.operationTime |  | keyword |
| shodan.host.mongodb.buildInfo.storageEngines |  | keyword |
| shodan.host.mongodb.buildInfo.sysInfo |  | keyword |
| shodan.host.mongodb.buildInfo.targetMinOS |  | keyword |
| shodan.host.mongodb.buildInfo.version |  | keyword |
| shodan.host.mongodb.buildInfo.versionArray |  | keyword |
| shodan.host.mongodb.listDatabases.databases.empty |  | keyword |
| shodan.host.mongodb.listDatabases.databases.name |  | keyword |
| shodan.host.mongodb.listDatabases.databases.sizeOnDisk |  | keyword |
| shodan.host.mongodb.listDatabases.ok |  | keyword |
| shodan.host.mongodb.listDatabases.totalSize |  | keyword |
| shodan.host.mongodb.serverStatus.asserts.msg |  | keyword |
| shodan.host.mongodb.serverStatus.asserts.regular |  | keyword |
| shodan.host.mongodb.serverStatus.asserts.rollovers |  | keyword |
| shodan.host.mongodb.serverStatus.asserts.user |  | keyword |
| shodan.host.mongodb.serverStatus.asserts.warning |  | keyword |
| shodan.host.mongodb.serverStatus.connections.active |  | keyword |
| shodan.host.mongodb.serverStatus.connections.available |  | keyword |
| shodan.host.mongodb.serverStatus.connections.current |  | keyword |
| shodan.host.mongodb.serverStatus.connections.totalCreated |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.averageCatchUpOps |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.catchUpTakeover.called |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.catchUpTakeover.successful |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.electionTimeout.called |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.electionTimeout.successful |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.freezeTimeout.called |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.freezeTimeout.successful |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUps |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsAlreadyCaughtUp |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsFailedWithError |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsFailedWithNewTerm |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsFailedWithReplSetAbortPrimaryCatchUpCmd |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsSkipped |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsSucceeded |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numCatchUpsTimedOut |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.numStepDownsCausedByHigherTerm |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.priorityTakeover.called |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.priorityTakeover.successful |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.stepUpCmd.called |  | keyword |
| shodan.host.mongodb.serverStatus.electionMetrics.stepUpCmd.successful |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.input_blocks |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.involuntary_context_switches |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.maximum_resident_set_kb |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.note |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.output_blocks |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.page_faults |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.page_reclaims |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.system_time_us |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.user_time_us |  | keyword |
| shodan.host.mongodb.serverStatus.extra_info.voluntary_context_switches |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.enabled |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.isLagged |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.isLaggedCount |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.isLaggedTimeMicros |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.locksPerOp |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.sustainerRate |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.targetRateLimit |  | keyword |
| shodan.host.mongodb.serverStatus.flowControl.timeAcquiringMicros |  | keyword |
| shodan.host.mongodb.serverStatus.freeMonitoring.state |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.activeClients.readers |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.activeClients.total |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.activeClients.writers |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.currentQueue.readers |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.currentQueue.total |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.currentQueue.writers |  | keyword |
| shodan.host.mongodb.serverStatus.globalLock.totalTime |  | keyword |
| shodan.host.mongodb.serverStatus.host |  | keyword |
| shodan.host.mongodb.serverStatus.localTime |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Collection.acquireCount.R |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Collection.acquireCount.W |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Collection.acquireCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Collection.acquireCount.w |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.acquireCount.R |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.acquireCount.W |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.acquireCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.acquireCount.w |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.acquireWaitCount.W |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.acquireWaitCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.timeAcquiringMicros.W |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Database.timeAcquiringMicros.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Global.acquireCount.W |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Global.acquireCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Global.acquireCount.w |  | keyword |
| shodan.host.mongodb.serverStatus.locks.Mutex.acquireCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.ParallelBatchWriterMode.acquireCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.locks.ReplicationStateTransition.acquireCount.w |  | keyword |
| shodan.host.mongodb.serverStatus.locks.oplog.acquireCount.r |  | keyword |
| shodan.host.mongodb.serverStatus.logicalSessionRecordCache.\* |  | keyword |
| shodan.host.mongodb.serverStatus.mem.\* |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.aggStageCounters.\* |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.commands.\*.failed |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.commands.\*.total |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.cursor.open.noTimeout |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.cursor.open.pinned |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.cursor.open.total |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.cursor.timedOut |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.document.deleted |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.document.inserted |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.document.returned |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.document.updated |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.getLastError.wtime.num |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.getLastError.wtime.totalMillis |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.getLastError.wtimeouts |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.operation.scanAndOrder |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.operation.writeConflicts |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.query.planCacheTotalSizeEstimateBytes |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.query.updateOneOpStyleBroadcastWithExactIDCount |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.queryExecutor.scanned |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.queryExecutor.scannedObjects |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.record.moves |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.apply.attemptsToBecomeSecondary |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.apply.batchSize |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.apply.batches.num |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.apply.batches.totalMillis |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.apply.ops |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.buffer.count |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.buffer.maxSizeBytes |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.buffer.sizeBytes |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.executor.networkInterface |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.executor.pool.inProgressCount |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.executor.queues.networkInProgress |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.executor.queues.sleepers |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.executor.shuttingDown |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.executor.unsignaledEvents |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.initialSync.completed |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.initialSync.failedAttempts |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.initialSync.failures |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.bytes |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.getmores.num |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.getmores.totalMillis |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.notMasterLegacyUnacknowledgedWrites |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.notMasterUnacknowledgedWrites |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.ops |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.readersCreated |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.network.replSetUpdatePosition.num |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.preload.docs.num |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.preload.docs.totalMillis |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.preload.indexes.num |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.preload.indexes.totalMillis |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.stateTransition.userOperationsKilled |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.stateTransition.userOperationsRunning |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.syncSource.numSelections |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.syncSource.numTimesChoseDifferent |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.syncSource.numTimesChoseSame |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.repl.syncSource.numTimesCouldNotFind |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.storage.freelist.search.bucketExhausted |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.storage.freelist.search.requests |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.storage.freelist.search.scanned |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.ttl.deletedDocuments |  | keyword |
| shodan.host.mongodb.serverStatus.metrics.ttl.passes |  | keyword |
| shodan.host.mongodb.serverStatus.network.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.snappy.compressor.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.snappy.compressor.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.snappy.decompressor.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.snappy.decompressor.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zlib.compressor.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zlib.compressor.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zlib.decompressor.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zlib.decompressor.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zstd.compressor.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zstd.compressor.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zstd.decompressor.bytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.compression.zstd.decompressor.bytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.numRequests |  | keyword |
| shodan.host.mongodb.serverStatus.network.physicalBytesIn |  | keyword |
| shodan.host.mongodb.serverStatus.network.physicalBytesOut |  | keyword |
| shodan.host.mongodb.serverStatus.network.serviceExecutorTaskStats.executor |  | keyword |
| shodan.host.mongodb.serverStatus.network.serviceExecutorTaskStats.threadsRunning |  | keyword |
| shodan.host.mongodb.serverStatus.ok |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.commands.latency |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.commands.ops |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.reads.latency |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.reads.ops |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.transactions.latency |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.transactions.ops |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.writes.latency |  | keyword |
| shodan.host.mongodb.serverStatus.opLatencies.writes.ops |  | keyword |
| shodan.host.mongodb.serverStatus.opReadConcernCounters.available |  | keyword |
| shodan.host.mongodb.serverStatus.opReadConcernCounters.linearizable |  | keyword |
| shodan.host.mongodb.serverStatus.opReadConcernCounters.local |  | keyword |
| shodan.host.mongodb.serverStatus.opReadConcernCounters.majority |  | keyword |
| shodan.host.mongodb.serverStatus.opReadConcernCounters.none |  | keyword |
| shodan.host.mongodb.serverStatus.opReadConcernCounters.snapshot |  | keyword |
| shodan.host.mongodb.serverStatus.opcounters.command |  | keyword |
| shodan.host.mongodb.serverStatus.opcounters.delete |  | keyword |
| shodan.host.mongodb.serverStatus.opcounters.getmore |  | keyword |
| shodan.host.mongodb.serverStatus.opcounters.insert |  | keyword |
| shodan.host.mongodb.serverStatus.opcounters.query |  | keyword |
| shodan.host.mongodb.serverStatus.opcounters.update |  | keyword |
| shodan.host.mongodb.serverStatus.opcountersRepl.command |  | keyword |
| shodan.host.mongodb.serverStatus.opcountersRepl.delete |  | keyword |
| shodan.host.mongodb.serverStatus.opcountersRepl.getmore |  | keyword |
| shodan.host.mongodb.serverStatus.opcountersRepl.insert |  | keyword |
| shodan.host.mongodb.serverStatus.opcountersRepl.query |  | keyword |
| shodan.host.mongodb.serverStatus.opcountersRepl.update |  | keyword |
| shodan.host.mongodb.serverStatus.pid |  | keyword |
| shodan.host.mongodb.serverStatus.process |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.backupCursorOpen |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.dropPendingIdents |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.name |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.oldestRequiredTimestampForCrashRecovery |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.persistent |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.readOnly |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.supportsCommittedReads |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.supportsPendingDrops |  | keyword |
| shodan.host.mongodb.serverStatus.storageEngine.supportsSnapshotReadConcern |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.generic.current_allocated_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.generic.heap_size |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.aggressive_memory_decommit |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.central_cache_free_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.current_total_thread_cache_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.formattedString |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.max_total_thread_cache_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_commit_count |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_committed_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_decommit_count |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_free_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_reserve_count |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_scavenge_count |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_total_commit_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_total_decommit_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_total_reserve_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.pageheap_unmapped_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.release_rate |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.spinlock_total_delay_ns |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.thread_cache_free_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.total_free_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.tcmalloc.tcmalloc.transfer_cache_free_bytes |  | keyword |
| shodan.host.mongodb.serverStatus.trafficRecording.running |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.currentActive |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.currentInactive |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.currentOpen |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.currentPrepared |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.retriedCommandsCount |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.retriedStatementsCount |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.totalAborted |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.totalCommitted |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.totalPrepared |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.totalPreparedThenAborted |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.totalPreparedThenCommitted |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.totalStarted |  | keyword |
| shodan.host.mongodb.serverStatus.transactions.transactionsCollectionWriteCount |  | keyword |
| shodan.host.mongodb.serverStatus.transportSecurity.\* |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.currentInSteps.deletingCoordinatorDoc |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.currentInSteps.waitingForDecisionAcks |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.currentInSteps.waitingForVotes |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.currentInSteps.writingDecision |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.currentInSteps.writingParticipantList |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.totalAbortedTwoPhaseCommit |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.totalCommittedTwoPhaseCommit |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.totalCreated |  | keyword |
| shodan.host.mongodb.serverStatus.twoPhaseCommitCoordinator.totalStartedTwoPhaseCommit |  | keyword |
| shodan.host.mongodb.serverStatus.uptime |  | keyword |
| shodan.host.mongodb.serverStatus.uptimeEstimate |  | keyword |
| shodan.host.mongodb.serverStatus.uptimeMillis |  | keyword |
| shodan.host.mongodb.serverStatus.version |  | keyword |
| shodan.host.mqtt.code |  | keyword |
| shodan.host.mqtt.messages.payload |  | keyword |
| shodan.host.mqtt.messages.topic |  | keyword |
| shodan.host.msrpc.actual_count |  | keyword |
| shodan.host.msrpc.towers.\*.annotation |  | keyword |
| shodan.host.msrpc.towers.\*.bindings.ncacn_ip_http |  | keyword |
| shodan.host.msrpc.towers.\*.bindings.ncacn_ip_tcp |  | keyword |
| shodan.host.msrpc.towers.\*.bindings.ncacn_np |  | keyword |
| shodan.host.msrpc.towers.\*.bindings.ncalrpc |  | keyword |
| shodan.host.msrpc.towers.\*.bindings.netbios |  | keyword |
| shodan.host.msrpc.towers.\*.protocol |  | keyword |
| shodan.host.msrpc.towers.\*.provider |  | keyword |
| shodan.host.msrpc.towers.\*.version |  | keyword |
| shodan.host.mssql_ssrp.instances.instance_name |  | keyword |
| shodan.host.mssql_ssrp.instances.is_clustered |  | keyword |
| shodan.host.mssql_ssrp.instances.np |  | keyword |
| shodan.host.mssql_ssrp.instances.server_name |  | keyword |
| shodan.host.mssql_ssrp.instances.tcp |  | keyword |
| shodan.host.mssql_ssrp.instances.version |  | keyword |
| shodan.host.mssql_ssrp.instances.version_name |  | keyword |
| shodan.host.mysql.authentication_plugin |  | keyword |
| shodan.host.mysql.capabilities |  | keyword |
| shodan.host.mysql.error_code |  | keyword |
| shodan.host.mysql.error_message |  | keyword |
| shodan.host.mysql.extended_server_capabilities |  | keyword |
| shodan.host.mysql.protocol_version |  | keyword |
| shodan.host.mysql.server_language |  | keyword |
| shodan.host.mysql.server_status |  | keyword |
| shodan.host.mysql.thread_id |  | keyword |
| shodan.host.mysql.version |  | keyword |
| shodan.host.mysqlx.authentication_mechanisms |  | keyword |
| shodan.host.mysqlx.client_interactive |  | keyword |
| shodan.host.mysqlx.client_pwd_expire_ok |  | keyword |
| shodan.host.mysqlx.compression.algorithm |  | keyword |
| shodan.host.mysqlx.doc_formats |  | keyword |
| shodan.host.mysqlx.node_type |  | keyword |
| shodan.host.mysqlx.tls |  | keyword |
| shodan.host.nats.auth_required |  | keyword |
| shodan.host.nats.client_id |  | keyword |
| shodan.host.nats.client_ip |  | keyword |
| shodan.host.nats.go |  | keyword |
| shodan.host.nats.headers |  | keyword |
| shodan.host.nats.host |  | keyword |
| shodan.host.nats.max_payload |  | keyword |
| shodan.host.nats.nonce |  | keyword |
| shodan.host.nats.port |  | keyword |
| shodan.host.nats.proto |  | keyword |
| shodan.host.nats.server_id |  | keyword |
| shodan.host.nats.server_name |  | keyword |
| shodan.host.nats.tls_required |  | keyword |
| shodan.host.nats.version |  | keyword |
| shodan.host.netbios.mac |  | keyword |
| shodan.host.netbios.names.flags |  | keyword |
| shodan.host.netbios.names.name |  | keyword |
| shodan.host.netbios.names.suffix |  | keyword |
| shodan.host.netbios.networks |  | keyword |
| shodan.host.netbios.raw |  | text |
| shodan.host.netbios.server_name |  | keyword |
| shodan.host.node_exporter.node_dmi_info.bios_date |  | keyword |
| shodan.host.node_exporter.node_dmi_info.bios_release |  | keyword |
| shodan.host.node_exporter.node_dmi_info.bios_vendor |  | keyword |
| shodan.host.node_exporter.node_dmi_info.bios_version |  | keyword |
| shodan.host.node_exporter.node_dmi_info.board_asset_tag |  | keyword |
| shodan.host.node_exporter.node_dmi_info.board_name |  | keyword |
| shodan.host.node_exporter.node_dmi_info.board_vendor |  | keyword |
| shodan.host.node_exporter.node_dmi_info.board_version |  | keyword |
| shodan.host.node_exporter.node_dmi_info.chassis_asset_tag |  | keyword |
| shodan.host.node_exporter.node_dmi_info.chassis_vendor |  | keyword |
| shodan.host.node_exporter.node_dmi_info.chassis_version |  | keyword |
| shodan.host.node_exporter.node_dmi_info.product_family |  | keyword |
| shodan.host.node_exporter.node_dmi_info.product_name |  | keyword |
| shodan.host.node_exporter.node_dmi_info.product_serial |  | keyword |
| shodan.host.node_exporter.node_dmi_info.product_sku |  | keyword |
| shodan.host.node_exporter.node_dmi_info.product_uuid |  | keyword |
| shodan.host.node_exporter.node_dmi_info.product_version |  | keyword |
| shodan.host.node_exporter.node_dmi_info.system_vendor |  | keyword |
| shodan.host.node_exporter.node_exporter_build_info.branch |  | keyword |
| shodan.host.node_exporter.node_exporter_build_info.goversion |  | keyword |
| shodan.host.node_exporter.node_exporter_build_info.revision |  | keyword |
| shodan.host.node_exporter.node_exporter_build_info.version |  | keyword |
| shodan.host.node_exporter.node_network_info.\*.address |  | keyword |
| shodan.host.node_exporter.node_network_info.\*.broadcast |  | keyword |
| shodan.host.node_exporter.node_network_info.\*.device |  | keyword |
| shodan.host.node_exporter.node_network_info.\*.duplex |  | keyword |
| shodan.host.node_exporter.node_network_info.\*.operstate |  | keyword |
| shodan.host.node_exporter.node_nvme_info.\*.device |  | keyword |
| shodan.host.node_exporter.node_nvme_info.\*.firmware_revision |  | keyword |
| shodan.host.node_exporter.node_nvme_info.\*.model |  | keyword |
| shodan.host.node_exporter.node_nvme_info.\*.serial |  | keyword |
| shodan.host.node_exporter.node_nvme_info.\*.state |  | keyword |
| shodan.host.node_exporter.node_os_info.build_id |  | keyword |
| shodan.host.node_exporter.node_os_info.id |  | keyword |
| shodan.host.node_exporter.node_os_info.id_like |  | keyword |
| shodan.host.node_exporter.node_os_info.name |  | keyword |
| shodan.host.node_exporter.node_os_info.pretty_name |  | keyword |
| shodan.host.node_exporter.node_os_info.version |  | keyword |
| shodan.host.node_exporter.node_os_info.version_codename |  | keyword |
| shodan.host.node_exporter.node_os_info.version_id |  | keyword |
| shodan.host.node_exporter.node_uname_info.domainname |  | keyword |
| shodan.host.node_exporter.node_uname_info.machine |  | keyword |
| shodan.host.node_exporter.node_uname_info.nodename |  | keyword |
| shodan.host.node_exporter.node_uname_info.release |  | keyword |
| shodan.host.node_exporter.node_uname_info.sysname |  | keyword |
| shodan.host.node_exporter.node_uname_info.version |  | keyword |
| shodan.host.ntlm.dns_domain_name |  | keyword |
| shodan.host.ntlm.dns_forest_name |  | keyword |
| shodan.host.ntlm.fqdn |  | keyword |
| shodan.host.ntlm.netbios_computer_name |  | keyword |
| shodan.host.ntlm.netbios_domain_name |  | keyword |
| shodan.host.ntlm.os |  | keyword |
| shodan.host.ntlm.os_build |  | keyword |
| shodan.host.ntlm.target_realm |  | keyword |
| shodan.host.ntlm.timestamp |  | date |
| shodan.host.ntp.clk_jitter |  | keyword |
| shodan.host.ntp.clk_wander |  | keyword |
| shodan.host.ntp.clock |  | keyword |
| shodan.host.ntp.clock_offset |  | keyword |
| shodan.host.ntp.delay |  | keyword |
| shodan.host.ntp.frequency |  | keyword |
| shodan.host.ntp.jitter |  | keyword |
| shodan.host.ntp.leap |  | keyword |
| shodan.host.ntp.mintc |  | keyword |
| shodan.host.ntp.monlist.connections |  | keyword |
| shodan.host.ntp.monlist.more |  | keyword |
| shodan.host.ntp.noise |  | keyword |
| shodan.host.ntp.offset |  | keyword |
| shodan.host.ntp.peer |  | keyword |
| shodan.host.ntp.poll |  | keyword |
| shodan.host.ntp.precision |  | keyword |
| shodan.host.ntp.processor |  | keyword |
| shodan.host.ntp.refid |  | keyword |
| shodan.host.ntp.reftime |  | keyword |
| shodan.host.ntp.root_delay |  | keyword |
| shodan.host.ntp.root_dispersion |  | keyword |
| shodan.host.ntp.rootdelay |  | keyword |
| shodan.host.ntp.rootdisp |  | keyword |
| shodan.host.ntp.rootdispersion |  | keyword |
| shodan.host.ntp.stability |  | keyword |
| shodan.host.ntp.state |  | keyword |
| shodan.host.ntp.stratum |  | keyword |
| shodan.host.ntp.sys_jitter |  | keyword |
| shodan.host.ntp.system |  | keyword |
| shodan.host.ntp.tc |  | keyword |
| shodan.host.ntp.version |  | keyword |
| shodan.host.openflow.version |  | keyword |
| shodan.host.opts.command |  | keyword |
| shodan.host.opts.command_length |  | keyword |
| shodan.host.opts.command_status |  | keyword |
| shodan.host.opts.data |  | text |
| shodan.host.opts.device_type |  | keyword |
| shodan.host.opts.encapsulation_length |  | keyword |
| shodan.host.opts.heartbleed |  | keyword |
| shodan.host.opts.ip |  | keyword |
| shodan.host.opts.item_count |  | keyword |
| shodan.host.opts.modbus.response |  | keyword |
| shodan.host.opts.modbus.uid |  | keyword |
| shodan.host.opts.options |  | keyword |
| shodan.host.opts.product_code |  | keyword |
| shodan.host.opts.product_name |  | keyword |
| shodan.host.opts.product_name_length |  | keyword |
| shodan.host.opts.raw |  | text |
| shodan.host.opts.revision_major |  | keyword |
| shodan.host.opts.revision_minor |  | keyword |
| shodan.host.opts.screenshot.data |  | text |
| shodan.host.opts.screenshot.hash |  | keyword |
| shodan.host.opts.screenshot.labels |  | keyword |
| shodan.host.opts.screenshot.mime |  | keyword |
| shodan.host.opts.screenshot.text |  | keyword |
| shodan.host.opts.sender_context |  | keyword |
| shodan.host.opts.serial |  | keyword |
| shodan.host.opts.session |  | keyword |
| shodan.host.opts.socket_addr |  | keyword |
| shodan.host.opts.state |  | keyword |
| shodan.host.opts.status |  | keyword |
| shodan.host.opts.type_id |  | keyword |
| shodan.host.opts.vendor_id |  | keyword |
| shodan.host.opts.version |  | keyword |
| shodan.host.opts.vulns |  | keyword |
| shodan.host.oracle_tnslsnr.description.err |  | keyword |
| shodan.host.oracle_tnslsnr.description.error_stack.error.code |  | keyword |
| shodan.host.oracle_tnslsnr.description.error_stack.error.emfi |  | keyword |
| shodan.host.oracle_tnslsnr.description.vsnnum |  | keyword |
| shodan.host.org |  | keyword |
| shodan.host.os |  | keyword |
| shodan.host.philips_hue.api_version |  | keyword |
| shodan.host.philips_hue.bridge_id |  | keyword |
| shodan.host.philips_hue.data_store_version |  | keyword |
| shodan.host.philips_hue.factory_new |  | keyword |
| shodan.host.philips_hue.mac |  | keyword |
| shodan.host.philips_hue.model_id |  | keyword |
| shodan.host.philips_hue.name |  | keyword |
| shodan.host.philips_hue.sw_version |  | keyword |
| shodan.host.platform |  | keyword |
| shodan.host.plex.machine_identifier |  | keyword |
| shodan.host.plex.version |  | keyword |
| shodan.host.port |  | keyword |
| shodan.host.pptp.firmware |  | keyword |
| shodan.host.pptp.hostname |  | keyword |
| shodan.host.pptp.vendor |  | keyword |
| shodan.host.product |  | keyword |
| shodan.host.qnap.apps.\*.build |  | keyword |
| shodan.host.qnap.apps.\*.checksum |  | keyword |
| shodan.host.qnap.apps.\*.version |  | keyword |
| shodan.host.qnap.firmware.build |  | keyword |
| shodan.host.qnap.firmware.number |  | keyword |
| shodan.host.qnap.firmware.version |  | keyword |
| shodan.host.qnap.hostname |  | keyword |
| shodan.host.qnap.model.display_model_name |  | keyword |
| shodan.host.qnap.model.internal_model_name |  | keyword |
| shodan.host.qnap.model.model_name |  | keyword |
| shodan.host.qnap.model.platform |  | keyword |
| shodan.host.qnap.model.platform_ex |  | keyword |
| shodan.host.qnap.myqnapcloud.url |  | keyword |
| shodan.host.rdp_encryption.levels |  | keyword |
| shodan.host.rdp_encryption.methods |  | keyword |
| shodan.host.rdp_encryption.protocols |  | keyword |
| shodan.host.redis.\*.\* |  | keyword |
| shodan.host.redis.authentication_required |  | keyword |
| shodan.host.rsync.authentication |  | keyword |
| shodan.host.rsync.modules.\* |  |  |
| shodan.host.screenshot.data |  | text |
| shodan.host.screenshot.hash |  | keyword |
| shodan.host.screenshot.labels |  | keyword |
| shodan.host.screenshot.mime |  | keyword |
| shodan.host.screenshot.text |  | keyword |
| shodan.host.smb.anonymous |  | keyword |
| shodan.host.smb.capabilities |  | keyword |
| shodan.host.smb.os |  | keyword |
| shodan.host.smb.raw |  | text |
| shodan.host.smb.shares.comments |  | keyword |
| shodan.host.smb.shares.files.directory |  | keyword |
| shodan.host.smb.shares.files.name |  | keyword |
| shodan.host.smb.shares.files.read-only |  | keyword |
| shodan.host.smb.shares.files.size |  | keyword |
| shodan.host.smb.shares.name |  | keyword |
| shodan.host.smb.shares.special |  | keyword |
| shodan.host.smb.shares.temporary |  | keyword |
| shodan.host.smb.shares.type |  | keyword |
| shodan.host.smb.smb_version |  | keyword |
| shodan.host.smb.software |  | keyword |
| shodan.host.snmp.contact |  | keyword |
| shodan.host.snmp.description |  | keyword |
| shodan.host.snmp.engine_boots |  | keyword |
| shodan.host.snmp.engine_time |  | keyword |
| shodan.host.snmp.engineid_data |  | keyword |
| shodan.host.snmp.engineid_format |  | keyword |
| shodan.host.snmp.enterprise |  | keyword |
| shodan.host.snmp.location |  | keyword |
| shodan.host.snmp.name |  | keyword |
| shodan.host.snmp.objectid |  | keyword |
| shodan.host.snmp.ordescr |  | keyword |
| shodan.host.snmp.orid |  | keyword |
| shodan.host.snmp.oruptime |  | keyword |
| shodan.host.snmp.service |  | keyword |
| shodan.host.snmp.uptime |  | keyword |
| shodan.host.snmp.versions |  | keyword |
| shodan.host.sonicwall.serial_number |  | keyword |
| shodan.host.sonos.friendly_name |  | keyword |
| shodan.host.sonos.hardware_version |  | keyword |
| shodan.host.sonos.mac_address |  | keyword |
| shodan.host.sonos.model_name |  | keyword |
| shodan.host.sonos.model_number |  | keyword |
| shodan.host.sonos.raw |  | text |
| shodan.host.sonos.room_name |  | keyword |
| shodan.host.sonos.serial_number |  | keyword |
| shodan.host.sonos.software_version |  | keyword |
| shodan.host.sonos.udn |  | keyword |
| shodan.host.sony_bravia.interface_version |  | keyword |
| shodan.host.sony_bravia.mac_address |  | keyword |
| shodan.host.sony_bravia.model_name |  | keyword |
| shodan.host.spotify_connect.brand_display_name |  | keyword |
| shodan.host.spotify_connect.client_id |  | keyword |
| shodan.host.spotify_connect.device_id |  | keyword |
| shodan.host.spotify_connect.device_type |  | keyword |
| shodan.host.spotify_connect.model_display_name |  | keyword |
| shodan.host.spotify_connect.public_key |  | keyword |
| shodan.host.spotify_connect.remote_name |  | keyword |
| shodan.host.spotify_connect.scope |  | keyword |
| shodan.host.spotify_connect.version |  | keyword |
| shodan.host.ssh.cipher |  | keyword |
| shodan.host.ssh.fingerprint |  | keyword |
| shodan.host.ssh.hassh |  | keyword |
| shodan.host.ssh.kex.compression_algorithms |  | keyword |
| shodan.host.ssh.kex.encryption_algorithms |  | keyword |
| shodan.host.ssh.kex.kex_algorithms |  | keyword |
| shodan.host.ssh.kex.kex_follows |  | keyword |
| shodan.host.ssh.kex.languages |  | keyword |
| shodan.host.ssh.kex.mac_algorithms |  | keyword |
| shodan.host.ssh.kex.server_host_key_algorithms |  | keyword |
| shodan.host.ssh.kex.unused |  | keyword |
| shodan.host.ssh.key |  | keyword |
| shodan.host.ssh.mac |  | keyword |
| shodan.host.ssh.type |  | keyword |
| shodan.host.ssl.acceptable_cas.components.C |  | keyword |
| shodan.host.ssl.acceptable_cas.components.CN |  | keyword |
| shodan.host.ssl.acceptable_cas.components.DC |  | keyword |
| shodan.host.ssl.acceptable_cas.components.L |  | keyword |
| shodan.host.ssl.acceptable_cas.components.O |  | keyword |
| shodan.host.ssl.acceptable_cas.components.OU |  | keyword |
| shodan.host.ssl.acceptable_cas.components.ST |  | keyword |
| shodan.host.ssl.acceptable_cas.components.UNDEF |  | keyword |
| shodan.host.ssl.acceptable_cas.components.businessCategory |  | keyword |
| shodan.host.ssl.acceptable_cas.components.description |  | keyword |
| shodan.host.ssl.acceptable_cas.components.dnQualifier |  | keyword |
| shodan.host.ssl.acceptable_cas.components.emailAddress |  | keyword |
| shodan.host.ssl.acceptable_cas.components.friendlyName |  | keyword |
| shodan.host.ssl.acceptable_cas.components.initials |  | keyword |
| shodan.host.ssl.acceptable_cas.components.jurisdictionC |  | keyword |
| shodan.host.ssl.acceptable_cas.components.name |  | keyword |
| shodan.host.ssl.acceptable_cas.components.organizationIdentifier |  | keyword |
| shodan.host.ssl.acceptable_cas.components.postalCode |  | keyword |
| shodan.host.ssl.acceptable_cas.components.serialNumber |  | keyword |
| shodan.host.ssl.acceptable_cas.components.street |  | keyword |
| shodan.host.ssl.acceptable_cas.components.title |  | keyword |
| shodan.host.ssl.acceptable_cas.hash |  | keyword |
| shodan.host.ssl.acceptable_cas.raw |  | text |
| shodan.host.ssl.alpn |  | keyword |
| shodan.host.ssl.cert.expired |  | boolean |
| shodan.host.ssl.cert.expires |  | keyword |
| shodan.host.ssl.cert.extensions.critical |  | keyword |
| shodan.host.ssl.cert.extensions.data |  | text |
| shodan.host.ssl.cert.extensions.name |  | keyword |
| shodan.host.ssl.cert.fingerprint.sha1 |  | keyword |
| shodan.host.ssl.cert.fingerprint.sha256 |  | keyword |
| shodan.host.ssl.cert.issued |  | keyword |
| shodan.host.ssl.cert.issuer.C |  | keyword |
| shodan.host.ssl.cert.issuer.CN |  | keyword |
| shodan.host.ssl.cert.issuer.DC |  | keyword |
| shodan.host.ssl.cert.issuer.L |  | keyword |
| shodan.host.ssl.cert.issuer.O |  | keyword |
| shodan.host.ssl.cert.issuer.OU |  | keyword |
| shodan.host.ssl.cert.issuer.SN |  | keyword |
| shodan.host.ssl.cert.issuer.ST |  | keyword |
| shodan.host.ssl.cert.issuer.UID |  | keyword |
| shodan.host.ssl.cert.issuer.contentType |  | keyword |
| shodan.host.ssl.cert.issuer.dnQualifier |  | keyword |
| shodan.host.ssl.cert.issuer.emailAddress |  | keyword |
| shodan.host.ssl.cert.issuer.initials |  | keyword |
| shodan.host.ssl.cert.issuer.name |  | keyword |
| shodan.host.ssl.cert.issuer.postalCode |  | keyword |
| shodan.host.ssl.cert.issuer.serialNumber |  | keyword |
| shodan.host.ssl.cert.issuer.street |  | keyword |
| shodan.host.ssl.cert.issuer.subjectAltName |  | keyword |
| shodan.host.ssl.cert.issuer.unstructuredAddress |  | keyword |
| shodan.host.ssl.cert.issuer.unstructuredName |  | keyword |
| shodan.host.ssl.cert.pubkey.bits |  | keyword |
| shodan.host.ssl.cert.pubkey.type |  | keyword |
| shodan.host.ssl.cert.serial |  | keyword |
| shodan.host.ssl.cert.sig_alg |  | keyword |
| shodan.host.ssl.cert.subject.C |  | keyword |
| shodan.host.ssl.cert.subject.CN |  | keyword |
| shodan.host.ssl.cert.subject.DC |  | keyword |
| shodan.host.ssl.cert.subject.L |  | keyword |
| shodan.host.ssl.cert.subject.O |  | keyword |
| shodan.host.ssl.cert.subject.OU |  | keyword |
| shodan.host.ssl.cert.subject.SN |  | keyword |
| shodan.host.ssl.cert.subject.ST |  | keyword |
| shodan.host.ssl.cert.subject.UID |  | keyword |
| shodan.host.ssl.cert.subject.businessCategory |  | keyword |
| shodan.host.ssl.cert.subject.contentType |  | keyword |
| shodan.host.ssl.cert.subject.dnQualifier |  | keyword |
| shodan.host.ssl.cert.subject.emailAddress |  | keyword |
| shodan.host.ssl.cert.subject.initials |  | keyword |
| shodan.host.ssl.cert.subject.jurisdictionC |  | keyword |
| shodan.host.ssl.cert.subject.jurisdictionL |  | keyword |
| shodan.host.ssl.cert.subject.jurisdictionST |  | keyword |
| shodan.host.ssl.cert.subject.name |  | keyword |
| shodan.host.ssl.cert.subject.organizationIdentifier |  | keyword |
| shodan.host.ssl.cert.subject.postOfficeBox |  | keyword |
| shodan.host.ssl.cert.subject.postalCode |  | keyword |
| shodan.host.ssl.cert.subject.serialNumber |  | keyword |
| shodan.host.ssl.cert.subject.street |  | keyword |
| shodan.host.ssl.cert.subject.subjectAltName |  | keyword |
| shodan.host.ssl.cert.subject.title |  | keyword |
| shodan.host.ssl.cert.subject.unstructuredAddress |  | keyword |
| shodan.host.ssl.cert.subject.unstructuredName |  | keyword |
| shodan.host.ssl.cert.subject.x500UniqueIdentifier |  | keyword |
| shodan.host.ssl.cert.version |  | keyword |
| shodan.host.ssl.chain |  | text |
| shodan.host.ssl.chain_sha256 |  | keyword |
| shodan.host.ssl.cipher.bits |  | keyword |
| shodan.host.ssl.cipher.name |  | keyword |
| shodan.host.ssl.cipher.version |  | keyword |
| shodan.host.ssl.dhparams.bits |  | keyword |
| shodan.host.ssl.dhparams.fingerprint |  | keyword |
| shodan.host.ssl.dhparams.generator |  | keyword |
| shodan.host.ssl.dhparams.prime |  | keyword |
| shodan.host.ssl.dhparams.public_key |  | keyword |
| shodan.host.ssl.handshake_states |  | text |
| shodan.host.ssl.ja3s |  | keyword |
| shodan.host.ssl.jarm |  | keyword |
| shodan.host.ssl.ocsp.cert_status |  | keyword |
| shodan.host.ssl.ocsp.certificate_id.hash_algorithm |  | keyword |
| shodan.host.ssl.ocsp.certificate_id.issuer_name_hash |  | keyword |
| shodan.host.ssl.ocsp.certificate_id.issuer_name_key |  | keyword |
| shodan.host.ssl.ocsp.certificate_id.serial_number |  | keyword |
| shodan.host.ssl.ocsp.next_update |  | keyword |
| shodan.host.ssl.ocsp.produced_at |  | keyword |
| shodan.host.ssl.ocsp.responder_id |  | keyword |
| shodan.host.ssl.ocsp.response_status |  | keyword |
| shodan.host.ssl.ocsp.signature_algorithm |  | keyword |
| shodan.host.ssl.ocsp.this_update |  | keyword |
| shodan.host.ssl.ocsp.version |  | keyword |
| shodan.host.ssl.tlsext.id |  | keyword |
| shodan.host.ssl.tlsext.name |  | keyword |
| shodan.host.ssl.trust.browser.apple |  | boolean |
| shodan.host.ssl.trust.browser.microsoft |  | boolean |
| shodan.host.ssl.trust.browser.mozilla |  | boolean |
| shodan.host.ssl.trust.is_revoked |  | boolean |
| shodan.host.ssl.trust.revoked.apple |  | keyword |
| shodan.host.ssl.trust.revoked.microsoft |  | keyword |
| shodan.host.ssl.trust.revoked.mozilla |  | keyword |
| shodan.host.ssl.versions |  | keyword |
| shodan.host.steam_a2s.app_id |  | keyword |
| shodan.host.steam_a2s.bots |  | keyword |
| shodan.host.steam_a2s.folder |  | keyword |
| shodan.host.steam_a2s.game |  | keyword |
| shodan.host.steam_a2s.game_port |  | keyword |
| shodan.host.steam_a2s.map |  | keyword |
| shodan.host.steam_a2s.max_players |  | keyword |
| shodan.host.steam_a2s.name |  | keyword |
| shodan.host.steam_a2s.os |  | keyword |
| shodan.host.steam_a2s.password |  | keyword |
| shodan.host.steam_a2s.players |  | keyword |
| shodan.host.steam_a2s.protocol |  | keyword |
| shodan.host.steam_a2s.secure |  | keyword |
| shodan.host.steam_a2s.server_type |  | keyword |
| shodan.host.steam_a2s.steam_id |  | keyword |
| shodan.host.steam_a2s.tags |  | keyword |
| shodan.host.steam_a2s.version |  | keyword |
| shodan.host.steam_ihs.client_id |  | keyword |
| shodan.host.steam_ihs.connect_port |  | keyword |
| shodan.host.steam_ihs.enabled_services |  | keyword |
| shodan.host.steam_ihs.euniverse |  | keyword |
| shodan.host.steam_ihs.hostname |  | keyword |
| shodan.host.steam_ihs.instance_id |  | keyword |
| shodan.host.steam_ihs.is_64bit |  | keyword |
| shodan.host.steam_ihs.min_version |  | keyword |
| shodan.host.steam_ihs.os_type |  | keyword |
| shodan.host.steam_ihs.public_ip_address |  | keyword |
| shodan.host.steam_ihs.timestamp |  | keyword |
| shodan.host.steam_ihs.users.auth_key_id |  | keyword |
| shodan.host.steam_ihs.users.steam_id |  | keyword |
| shodan.host.steam_ihs.version |  | keyword |
| shodan.host.stun.server_ip |  | keyword |
| shodan.host.stun.software |  | keyword |
| shodan.host.synology_dsm.custom_login_title |  | keyword |
| shodan.host.synology_dsm.hostname |  | keyword |
| shodan.host.synology_dsm.login_welcome_msg |  | keyword |
| shodan.host.synology_dsm.login_welcome_title |  | keyword |
| shodan.host.synology_srm.hostname |  | keyword |
| shodan.host.tags |  | keyword |
| shodan.host.telnet.do |  | keyword |
| shodan.host.telnet.dont |  | keyword |
| shodan.host.telnet.will |  | keyword |
| shodan.host.telnet.wont |  | keyword |
| shodan.host.timestamp |  | date |
| shodan.host.title |  | keyword |
| shodan.host.trane.equipment.device_name |  | keyword |
| shodan.host.trane.equipment.display_name |  | keyword |
| shodan.host.trane.equipment.equipment_family |  | keyword |
| shodan.host.trane.equipment.equipment_uri |  | keyword |
| shodan.host.trane.equipment.is_offline |  | keyword |
| shodan.host.trane.equipment.role_document |  | keyword |
| shodan.host.trane.hardware_serial_number |  | keyword |
| shodan.host.trane.hardware_type |  | keyword |
| shodan.host.trane.kernel_version |  | keyword |
| shodan.host.trane.product_name |  | keyword |
| shodan.host.trane.server_boot_time |  | keyword |
| shodan.host.trane.server_name |  | keyword |
| shodan.host.trane.server_time |  | keyword |
| shodan.host.trane.vendor_name |  | keyword |
| shodan.host.transport |  | keyword |
| shodan.host.ubiquiti.hostname |  | keyword |
| shodan.host.ubiquiti.ip |  | keyword |
| shodan.host.ubiquiti.ip_alt |  | keyword |
| shodan.host.ubiquiti.mac |  | keyword |
| shodan.host.ubiquiti.mac_alt |  | keyword |
| shodan.host.ubiquiti.product |  | keyword |
| shodan.host.ubiquiti.version |  | keyword |
| shodan.host.unitronics_pcom.hardware_version |  | keyword |
| shodan.host.unitronics_pcom.model |  | keyword |
| shodan.host.unitronics_pcom.os_build |  | keyword |
| shodan.host.unitronics_pcom.os_version |  | keyword |
| shodan.host.unitronics_pcom.plc_name |  | keyword |
| shodan.host.unitronics_pcom.plc_unique_id |  | keyword |
| shodan.host.unitronics_pcom.uid_master |  | keyword |
| shodan.host.upnp.device_type |  | keyword |
| shodan.host.upnp.friendly_name |  | keyword |
| shodan.host.upnp.manufacturer |  | keyword |
| shodan.host.upnp.manufacturer_url |  | keyword |
| shodan.host.upnp.model_description |  | keyword |
| shodan.host.upnp.model_name |  | keyword |
| shodan.host.upnp.model_number |  | keyword |
| shodan.host.upnp.model_url |  | keyword |
| shodan.host.upnp.presentation_url |  | keyword |
| shodan.host.upnp.serial_number |  | keyword |
| shodan.host.upnp.services.control_url |  | keyword |
| shodan.host.upnp.services.event_sub_url |  | keyword |
| shodan.host.upnp.services.scpdurl |  | keyword |
| shodan.host.upnp.services.service_id |  | keyword |
| shodan.host.upnp.services.service_type |  | keyword |
| shodan.host.upnp.sub_devices.device_type |  | keyword |
| shodan.host.upnp.sub_devices.friendly_name |  | keyword |
| shodan.host.upnp.sub_devices.manufacturer |  | keyword |
| shodan.host.upnp.sub_devices.manufacturer_url |  | keyword |
| shodan.host.upnp.sub_devices.model_description |  | keyword |
| shodan.host.upnp.sub_devices.model_name |  | keyword |
| shodan.host.upnp.sub_devices.model_number |  | keyword |
| shodan.host.upnp.sub_devices.model_url |  | keyword |
| shodan.host.upnp.sub_devices.serial_number |  | keyword |
| shodan.host.upnp.sub_devices.services.control_url |  | keyword |
| shodan.host.upnp.sub_devices.services.event_sub_url |  | keyword |
| shodan.host.upnp.sub_devices.services.scpdurl |  | keyword |
| shodan.host.upnp.sub_devices.services.service_id |  | keyword |
| shodan.host.upnp.sub_devices.services.service_type |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.device_type |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.friendly_name |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.manufacturer |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.manufacturer_url |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.model_description |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.model_name |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.model_number |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.model_url |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.serial_number |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.services.control_url |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.services.event_sub_url |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.services.scpdurl |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.services.service_id |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.services.service_type |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.udn |  | keyword |
| shodan.host.upnp.sub_devices.sub_devices.upc |  | keyword |
| shodan.host.upnp.sub_devices.udn |  | keyword |
| shodan.host.upnp.sub_devices.upc |  | keyword |
| shodan.host.upnp.udn |  | keyword |
| shodan.host.upnp.upc |  | keyword |
| shodan.host.version |  | keyword |
| shodan.host.vertx.firmware_date |  | keyword |
| shodan.host.vertx.firmware_version |  | keyword |
| shodan.host.vertx.internal_ip |  | keyword |
| shodan.host.vertx.mac |  | keyword |
| shodan.host.vertx.name |  | keyword |
| shodan.host.vertx.type |  | keyword |
| shodan.host.vmware.alternate_names |  | keyword |
| shodan.host.vmware.api_type |  | keyword |
| shodan.host.vmware.api_version |  | keyword |
| shodan.host.vmware.build |  | keyword |
| shodan.host.vmware.full_name |  | keyword |
| shodan.host.vmware.locale_build |  | keyword |
| shodan.host.vmware.locale_version |  | keyword |
| shodan.host.vmware.name |  | keyword |
| shodan.host.vmware.os_type |  | keyword |
| shodan.host.vmware.product_line_id |  | keyword |
| shodan.host.vmware.release_date |  | keyword |
| shodan.host.vmware.vendor |  | keyword |
| shodan.host.vmware.version |  | keyword |
| shodan.host.vnc.protocol_version |  | keyword |
| shodan.host.vnc.security_types.\* |  | keyword |
| shodan.host.vulns.\*.cvss |  | keyword |
| shodan.host.vulns.\*.references |  | keyword |
| shodan.host.vulns.\*.summary |  | text |
| shodan.host.vulns.\*.verified |  | boolean |
| shodan.host.xiaomi_miio.device_id |  | keyword |
| shodan.host.xiaomi_miio.token |  | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.kernel | Operating system kernel version as a raw string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| user_agent.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |
| vulnerability.category |  | keyword |
| vulnerability.classification |  | keyword |
| vulnerability.description |  | match_only_text |
| vulnerability.enumeration |  | keyword |
| vulnerability.id |  | keyword |
| vulnerability.reference |  | keyword |
| vulnerability.report_id |  | keyword |
| vulnerability.scanner.vendor |  | keyword |
| vulnerability.score.base |  | float |
| vulnerability.score.environmental |  | float |
| vulnerability.score.temporal |  | float |
| vulnerability.score.version |  | keyword |
| vulnerability.severity |  | keyword |
| vulnerability.verified |  | boolean |


An example event for `host` looks as following:

```json
{
    "@timestamp": "2023-02-20T14:52:30.000Z",
    "agent": {
        "ephemeral_id": "fa20256c-9510-435e-bf56-6c44ba7e36d3",
        "id": "34fc8d2b-8e71-4f01-bb7b-aeed64bc84ff",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.1"
    },
    "data_stream": {
        "dataset": "shodan.host",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "34fc8d2b-8e71-4f01-bb7b-aeed64bc84ff",
        "snapshot": false,
        "version": "8.6.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "shodan.host",
        "ingested": "2023-02-23T06:15:03Z",
        "kind": "alert",
        "original": "{\"_shodan\":{\"crawler\":\"487814a778c983e2dcef234806292d88c5cbf3ec\",\"id\":\"8f52c055-77f6-42bf-8b1c-e1a230924c46\",\"module\":\"dns-udp\",\"options\":{},\"ptr\":true},\"asn\":\"AS13335\",\"data\":\"\\nRecursion: enabled\",\"dns\":{\"recursive\":true,\"resolver_hostname\":null,\"resolver_id\":null,\"software\":null},\"domains\":[\"one.one\"],\"hash\":-553166942,\"hostnames\":[\"one.one.one.one\"],\"ip\":16843009,\"ip_str\":\"1.1.1.1\",\"isp\":\"Cloudflare, Inc.\",\"location\":{\"area_code\":null,\"city\":\"Miami\",\"country_code\":\"US\",\"country_code3\":null,\"country_name\":\"United States\",\"dma_code\":null,\"latitude\":25.7867,\"longitude\":-80.18,\"postal_code\":null,\"region_code\":\"FL\"},\"opts\":{\"raw\":\"34ef818500010000000000000776657273696f6e0462696e640000100003\"},\"org\":\"APNIC and Cloudflare DNS Resolver project\",\"os\":null,\"port\":53,\"timestamp\":\"2023-02-20T14:52:30Z\",\"transport\":\"udp\"}",
        "risk_score": 21,
        "severity": 21,
        "type": [
            "info"
        ]
    },
    "headers": {
        "accept_encoding": [
            "gzip"
        ],
        "content_length": [
            "824"
        ],
        "content_type": [
            "application/json"
        ],
        "shodan_alert_id": [
            "test"
        ],
        "shodan_alert_name": [
            "Alert Name"
        ],
        "shodan_alert_trigger": [
            "Trigger"
        ],
        "user_agent": [
            "Go-http-client/1.1"
        ]
    },
    "host": {
        "domain": "one.one",
        "hostname": "one.one.one.one",
        "ip": [
            "1.1.1.1"
        ],
        "name": "one.one.one.one"
    },
    "http": {
        "request": {
            "headers": {
                "accept_encoding": "gzip",
                "content_length": "824",
                "content_type": "application/json",
                "shodan_alert_id": "test",
                "shodan_alert_name": "Alert Name",
                "shodan_alert_trigger": "Trigger",
                "user_agent": "Go-http-client/1.1"
            }
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "message": "Shodan Monitor: Alert Name / Trigger",
    "network": {
        "protocol": "dns-udp",
        "transport": "udp"
    },
    "related": {
        "hosts": [
            "one.one",
            "one.one.one.one"
        ],
        "ip": [
            "1.1.1.1"
        ]
    },
    "server": {
        "address": [
            "1.1.1.1"
        ],
        "domain": "one.one",
        "ip": [
            "1.1.1.1"
        ],
        "port": 53
    },
    "shodan": {
        "alert": {
            "id": "test",
            "name": "Alert Name",
            "trigger": "Trigger"
        },
        "host": {
            "_shodan": {
                "crawler": "487814a778c983e2dcef234806292d88c5cbf3ec",
                "id": "8f52c055-77f6-42bf-8b1c-e1a230924c46",
                "module": "dns-udp",
                "ptr": true
            },
            "asn": "AS13335",
            "data": "\nRecursion: enabled",
            "dns": {
                "recursive": true
            },
            "domains": [
                "one.one"
            ],
            "hash": "-553166942",
            "hostnames": [
                "one.one.one.one"
            ],
            "ip": "16843009",
            "ip_str": "1.1.1.1",
            "isp": "Cloudflare, Inc.",
            "location": {
                "city": "Miami",
                "country_code": "US",
                "country_name": "United States",
                "latitude": "25.7867",
                "longitude": "-80.18",
                "region_code": "FL"
            },
            "opts": {
                "raw": "34ef818500010000000000000776657273696f6e0462696e640000100003"
            },
            "org": "APNIC and Cloudflare DNS Resolver project",
            "port": "53",
            "timestamp": "2023-02-20T14:52:30Z",
            "transport": "udp"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded"
    ]
}
```
