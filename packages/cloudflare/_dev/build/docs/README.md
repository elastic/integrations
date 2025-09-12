# Cloudflare Integration

Cloudflare integration uses [Cloudflare's API](https://api.cloudflare.com/) to retrieve [audit logs](https://support.cloudflare.com/hc/en-us/articles/115002833612-Understanding-Cloudflare-Audit-Logs) from the Cloudflare account and [Cloudflare's Logpull API](https://developers.cloudflare.com/logs/logpull/) to retrieve [traffic logs](https://developers.cloudflare.com/logs/logpull/understanding-the-basics/) from Cloudflare, for a particular zone, and ingest them into Elasticsearch. This allows you to search, observe and visualize the Cloudflare log events through Elasticsearch.

Users of [Cloudflare](https://www.cloudflare.com/en-au/learning/what-is-cloudflare/) use Cloudflare services to increase the security and performance of their web sites and services. 

> Note: Logpull is considered a legacy feature and it is recommended to use the [Cloudflare Logpush](https://www.elastic.co/docs/reference/integrations/cloudflare_logpush) integration for Cloudflare traffic logs for better performance and functionality. See [here](https://developers.cloudflare.com/logs/logpull/) for more details.

>  Note: Authenticating with API Key (Auth Key) using `X-AUTH-EMAIL` and `X-AUTH-KEY` is considered to be a legacy feature with several limitations that makes it less secure than API token (Auth Token). See [here](https://developers.cloudflare.com/fundamentals/api/get-started/keys/#limitations) for more information on API Key limitations.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In the "Search for integrations" search bar type **Cloudflare**.
3. Click on "Cloudflare" integration from the search results.
4. Click on **Add Cloudflare** button to add Cloudflare integration.

### Configure Cloudflare Audit logs

The integration can retrieve Cloudflare audit logs using -

1. Auth Email and Auth Key
2. Auth Token

More information is available [here](https://developers.cloudflare.com/logs/logpull/requesting-logs/#required-authentication-headers).

#### Configure using Auth Email and Auth Key

Enter values "Auth Email", "Auth Key" and "Account ID".

1. **Auth Email** is the email address associated with your account. 
2. **Auth Key** is the Global API key generated on the "My Profile" > "API Tokens" page.
3. **Account ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

>  Note: See [here](https://developers.cloudflare.com/fundamentals/api/get-started/keys/) for more information on `X-AUTH-EMAIL` and `X-AUTH-KEY`.

#### Configure using Auth Token

Enter values "Auth Token" and "Account ID".

For the Cloudflare integration to be able to successfully get logs, one of the following permissions must be granted to the API Token -

- Account Settings Write, Account Settings Read

1. **Auth Token** is the API Token generated on the "My Profile" > "API Tokens" or "Manage Account" > "Account API Tokens" page.
2. **Account ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

>  Note: See [here](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) for more information on `API Token`.

### Configure Cloudflare Logpull logs

These logs contain data related to the connecting client, the request path through the Cloudflare network, and the response from the origin web server. For more information see [here](https://developers.cloudflare.com/logs/logpull/).

The integration can retrieve Cloudflare logs using -

1. Auth Email and Auth Key
2. Auth Token

More information is available [here](https://developers.cloudflare.com/logs/logpull/requesting-logs/#required-authentication-headers).

#### Configure using Auth Email and Auth Key

Enter values "Auth Email", "Auth Key" and "Zone ID".

1. **Auth Email** is the email address associated with your account. 
2. **Auth Key** is the Global API key generated on the "My Profile" > "API Tokens" page.
3. **Zone ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

>  Note: See [here](https://developers.cloudflare.com/fundamentals/api/get-started/keys/) for more information on `X-AUTH-EMAIL` and `X-AUTH-KEY`.

#### Configure using Auth Token

Enter values "Auth Token" and "Zone ID".

For the Cloudflare integration to be able to successfully get logs the following permissions must be granted to the API Token -

- Account.Access: Audit Logs: Read

1. **Auth Token** is the API Token generated on the "My Profile" > "API Tokens" or "Manage Account" > "Account API Tokens" page.
2. **Zone ID** can be found [here](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/find-account-and-zone-ids/).

>  Note: See [here](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) for more information on `API Token`.

## Logs

### Audit

Audit logs summarize the history of changes made within your Cloudflare account.  Audit logs include account-level actions like login and logout, as well as setting changes to DNS, Crypto, Firewall, Speed, Caching, Page Rules, Network, and Traffic features, etc.

{{fields "audit"}}

{{event "audit"}}

### Logpull

These logs contain data related to the connecting client, the request path through the Cloudflare network, and the response from the origin web server. For more information see [here](https://developers.cloudflare.com/logs/logpull/).

{{fields "logpull"}}

{{event "logpull"}}