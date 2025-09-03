# DomainTools Feeds

DomainTools Feeds provide data on the different stages of the domain lifecycle: from first-observed in the wild, to newly re-activated after a period of quiet. Access current feed data in real-time or retrieve historical feed data through separate APIs. Some feeds also offer data for DNS firewalls in Response Policy Zone (RPZ) format.

Summary of Available Feeds:

- `Newly Active Domains (NAD)`: Apex-level domains (e.g. example.com but not <www.example.com>) that we observe based on the latest lifecycle of the domain. A domain may be seen either for the first time ever, or again after at least 10 days of inactivity (no observed resolutions in DNS). Populated with our global passive DNS (pDNS) sensor network.
- `Newly Observed Domains (NOD)`: Apex-level domains (e.g. example.com but not <www.example.com>) that we observe for the first time, and have not observed previously with our global DNS sensor network.
- `Domain Discovery`: New domains as they are either discovered in domain registration information, observed by our global sensor network, or reported by trusted third parties.
- `Domain RDAP`: Changes to global domain registration information, populated by the Registration Data Access Protocol (RDAP). Compliments the 5-Minute WHOIS Feed as registries and registrars switch from Whois to RDAP.

With over 300,000 new domains observed daily, the feed empowers security teams to identify and block potentially malicious domains before they can be weaponized.
Ideal for threat hunting, phishing prevention, and brand protection.

For example, if you wanted to monitor Newly Observed Domains (NOD) feed, you could ingest the DomainTools NOD feed.
Then you can reference ti_domaintools.nod_feed when using visualizations or alerts.

## Data streams

The DomainTools Feeds integration collects one type of data streams: **logs**

Log data streams collected by the DomainTools integration include the following feeds:

- `Newly Observed Domains (NOD)`
- `Newly Active Domains (NAD)`
- `Domain Discovery`
- `Domain RDAP`

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You will require a license to one or more DomainTools feeds, and API credentials.
Your required API credentials will vary with your authentication method, detailed below.

Obtain your API credentials from your group’s API administrator.
API administrators can manage their API keys at research.domaintools.com, selecting the drop-down account menu and choosing API admin.

## Setup

For step-by-step instructions on how to set up an integration, see the Getting started guide.

### Newly Observed Domains (NOD) Feed

The `nod_feed` data stream provides events from [DomainTools Newly Observed Domains Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "nod_feed"}}

{{fields "nod_feed"}}

### Newly Active Domains (NAD) Feed

The `nod_feed` data stream provides events from [DomainTools Newly Active Domains Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "nad_feed"}}

{{fields "nad_feed"}}

### Domain Discovery Feed

The `domaindiscovery_feed` data stream provides events from [DomainTools Domain Discovery Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "domaindiscovery_feed"}}

{{fields "domaindiscovery_feed"}}

### Domain RDAP Feed

The `domainrdap_feed` data stream provides events from [DomainTools Domain RDAP](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "domainrdap_feed"}}

{{fields "domainrdap_feed"}}
