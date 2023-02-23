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

{{fields "host"}}

{{event "host"}}
