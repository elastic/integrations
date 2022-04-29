# Cloudflare Integration

Users of [Cloudflare](https://www.cloudflare.com/en-au/learning/what-is-cloudflare/) use Cloudflare services for the purposes of increasing security and performance of their web sites and services. 

Cloudflare integration uses [Cloudflare's API](https://api.cloudflare.com/) to retrieve Audit events and network traffic logs from Cloudflare and ingest them into Elasticsearch. This allows you to search, observe and visualize the Cloudflare log events through Elasticsearch.

The Elastic agent running this integration interacts with the Cloudflare infrastructure using Cloudflare APIs to retrieve [audit logs](https://support.cloudflare.com/hc/en-us/articles/115002833612-Understanding-Cloudflare-Audit-Logs) and [traffic logs](https://developers.cloudflare.com/logs/logpull/understanding-the-basics/) for a particular zone.

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

NOTE: See for `X-AUTH-EMAIL` and `X-AUTH-KEY` [here](https://api.cloudflare.com/#getting-started-requests) for more information on Auth Email and Auth Key.

#### Configure using API Token

Enter values "API Token" and "Zone ID".

For the Cloudflare integration to be able to successfully get logs the following permissions must be granted to the API token -

- Account.Access: Audit Logs: Read

1. [**API Tokens**](https://developers.cloudflare.com/api/tokens/) allow for more granular permission settings. 
2. **Zone ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

## Logs

### Audit

Audit logs summarize the history of changes made within your Cloudflare account.  Audit logs include account-level actions like login and logout, as well as setting changes to DNS, Crypto, Firewall, Speed, Caching, Page Rules, Network, and Traffic features, etc.

{{fields "audit"}}

{{event "audit"}}

### Logpull

These logs contain data related to the connecting client, the request path through the Cloudflare network, and the response from the origin web server. For more information see [here](https://developers.cloudflare.com/logs/logpull/).

{{fields "logpull"}}

{{event "logpull"}}
