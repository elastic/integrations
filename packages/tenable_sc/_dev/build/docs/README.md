# Tenable.sc

The Tenable.sc integration collects and parses data from the Tenable.sc APIs.

## Compatibility

This module has been tested against `Tenable.sc version 5.18`

## Requirements

In order to ingest data from the Tenable.sc you must have the **Access key** and **Secret Key**.
Enable API keys to allow users to perform API key authentication as described [here](https://docs.tenable.com/tenablesc/Content/EnableAPIKeys.htm).

Generate API keys:
- Log in to **Tenable.sc Admin account** via the user interface.
- Click **Users > Users**.
- In the row for the user for which you want to generate an API key, click the settings icon. It would open `actions menu`.
- On the actions menu Click **Generate API Key**.
- On the confirmation window appears Click **Generate**.
- The Your API Key window appears, displaying the access key and secret key for the user.
- Use the keys in the Tenable.sc Integration configuration parameters.

## Logs

### Asset

This is the `asset` dataset.

{{event "asset"}}

{{fields "asset"}}

### Plugin

This is the `plugin` dataset.

{{event "plugin"}}

{{fields "plugin"}}

### Vulnerability

This is the `vulnerability` dataset.

{{event "vulnerability"}}

{{fields "vulnerability"}}