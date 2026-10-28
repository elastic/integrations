# DomainTools Feeds

DomainTools Feeds provide data on the different stages of the domain lifecycle: from first-observed in the wild, to newly re-activated after a period of quiet. Access current feed data in real-time or retrieve historical feed data through separate APIs. Some feeds also offer data for DNS firewalls in Response Policy Zone (RPZ) format.

Summary of Available Feeds:

- `Newly Active Domains (NAD)`: Apex-level domains (e.g. example.com but not <www.example.com>) that we observe based on the latest lifecycle of the domain. A domain may be seen either for the first time ever, or again after at least 10 days of inactivity (no observed resolutions in DNS). Populated with our global passive DNS (pDNS) sensor network.
- `Newly Observed Domains (NOD)`: Apex-level domains (e.g. example.com but not <www.example.com>) that we observe for the first time, and have not observed previously with our global DNS sensor network.
- `Domain Discovery`: New domains as they are either discovered in domain registration information, observed by our global sensor network, or reported by trusted third parties.
- `Domain RDAP`: Changes to global domain registration information, populated by the Registration Data Access Protocol (RDAP). Compliments the 5-Minute WHOIS Feed as registries and registrars switch from Whois to RDAP.
- `Domain Risk`: Real-time updates to Domain Risk Scores for apex domains, regardless of observed traffic.
- `Domain Hotlist`: Domains with high Domain Risk Scores that have also been active within 24 hours.

With over 300,000 new domains observed daily, the feed empowers security teams to identify and block potentially malicious domains before they can be weaponized.
Ideal for threat hunting, phishing prevention, and brand protection.

For example, if you wanted to monitor Newly Observed Domains (NOD) feed, you could ingest the DomainTools NOD feed.
Then you can reference ti_domaintools.nod_feed when using visualizations or alerts.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The DomainTools Feeds integration collects one type of data streams: **logs**

Log data streams collected by the DomainTools integration include the following feeds:

- `Newly Observed Domains (NOD)`
- `Newly Active Domains (NAD)`
- `Domain Discovery`
- `Domain RDAP`
- `Domain Risk`
- `Domain Hotlist`

## Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_domaintools.domaindiscovery_feed-*` | `logs-ti_domaintools.domaindiscovery_feed-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |
| `logs-ti_domaintools.domainhotlist_feed-*` | `logs-ti_domaintools.domainhotlist_feed-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |
| `logs-ti_domaintools.domainrdap_feed-*` | `logs-ti_domaintools.domainrdap_feed-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |
| `logs-ti_domaintools.domainrisk_feed-*` | `logs-ti_domaintools.domainrisk_feed-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |
| `logs-ti_domaintools.nad_feed-*` | `logs-ti_domaintools.nad_feed-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |
| `logs-ti_domaintools.nod_feed-*` | `logs-ti_domaintools.nod_feed-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_domaintools.domaindiscovery_feed-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

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

The `nad_feed` data stream provides events from [DomainTools Newly Active Domains Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
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

### Domain Risk Feed

The `domainrisk_feed` data stream provides events from [DomainTools Domain Risk](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "domainrisk_feed"}}

{{fields "domainrisk_feed"}}

### Domain Hotlist Feed

The `domainhotlist_feed` data stream provides events from [DomainTools Domain Hotlist](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "domainhotlist_feed"}}

{{fields "domainhotlist_feed"}}
