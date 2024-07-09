# Lumos Integration

The Lumos integration uses [Lumos' API](https://api.lumos.com/) to retrieve Activity Logs and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Activity Logs through Elasticsearch.

The Elastic agent running this integration interacts with Lumos' infrastructure using their APIs to retrieve [Activity Logs](https://api.lumos.com/activity_logs) for a Lumos tenant.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In the "Search for integrations" search bar type **Lumos**.
3. Click on "Lumos" integration from the search results.
4. Click on **Add Lumos** button to add Lumos integration.

### Configure Lumos Activity Logs data stream

1. In Lumos go to **Settings > API Tokens**
2. Click on "Add API Token", enter a name and description
3. Copy the key starting with `lsk_`
4. While adding Lumos integration in Elastic, paste your key into the `API Token` field

## Logs

### Activity Logs

Activity Logs summarize the history of changes and events occurring within Lumos.

{{fields "activity_logs"}}

{{event "activity_logs"}}