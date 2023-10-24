# Zoom Webhook Integration

This integration creates an HTTP listener that accepts incoming webhook
callbacks from Zoom.

To configure Zoom to send webhooks to this integration, please follow the
[Zoom Documentation](https://developers.zoom.us/docs/api/rest/webhook-only-app).

The agent running this integration must be able to accept requests from the
Internet in order for Zoom to be able connect. Zoom requires that the webhook
accept requests over HTTPS. So you must either configure the integration with
a valid TLS certificate or use a reverse proxy in front of the integration.

## Compatibility

This integration is compatible with the Zoom Platform API as of September 2020.

{{fields "webhook"}}
