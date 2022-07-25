# Alienvault OTX Integration

This integration is for [Alienvault OTX](https://otx.alienvault.com/api). It retrieves indicators for all pulses subscribed to a specific user account on OTX

## Configuration

To use this package, it is required to have an account on [Alienvault OTX](https://otx.alienvault.com/). Once an account has been created, and at least 1 pulse has been subscribed to, the API key can be retrieved from your [user profile dashboard](https://otx.alienvault.com/api). In the top right corner there should be an OTX KEY.

## Logs

### Threat

Retrieves all the related indicators over time, related to your pulse subscriptions on OTX.

{{fields "threat"}}

{{event "threat"}}
