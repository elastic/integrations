# DomainTools Real Time Unified Feeds

The DomainTools Real Time Unified Feeds integration allows you to monitor DomainTools Newly Observed Domains. 
The DomainTools NOD Feed provides real-time access to newly registered and observed domains, enabling proactive threat detection and defense. 

With over 300,000 new domains observed daily, the feed empowers security teams to identify and block potentially malicious domains before they can be weaponized. 
Ideal for threat hunting, phishing prevention, and brand protection, the NOD Feed delivers unparalleled visibility into emerging domain activity to stay ahead of evolving threats.

For example, if you wanted to monitor Newly Observed Domains (NOD) feed, you could ingest the DomainTools NOD feed. 
Then you can reference domaintools.nod_feed when using visualizations or alerts.

## Data streams

The DomainTools Real Time Unified Feeds integration collects one type of data streams: logs

Log data streams collected by the DomainTools integration include the Newly Observed Domains (NOD) feed: Apex-level domains (e.g. Example Domain  but not www.example.com) that we observe for the first time, and have not observed previously. 
Populated with our global DNS sensor network.

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
This data is collected via the [DomainTools Real Time Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

{{event "nod_feed"}}

{{fields "nod_feed"}}

