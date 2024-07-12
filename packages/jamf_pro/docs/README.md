# JAMF Pro

The JAMF Pro integration allows you to monitor devices controlled by JAMF Pro dashboard 


Use the JAMF Pro integration to {purpose}. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference {data stream type} when troubleshooting an issue.

For example, if you wanted to {sample use case} you could {action}. Then you can {visualize|alert|troubleshoot} by {action}.

## Data streams

 * __general_data__ provides basic information on devices - numbers, versions.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.  
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.  
You need JAMF Pro active license and OAuth2 credentials via API App  
JAMF API application permissions required:  
 * Read Computer Inventory Collection
 * Read Mobile devices
 * Read Computers
 * Read Mobile Device Inventory Collection

## Setup

To create a connection to JAMF Pro [application must be created](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) first. Credentials will be required

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- If applicable -->
<!-- ## Metrics reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->
