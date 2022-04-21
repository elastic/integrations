# Tenable.sc

The Tenable.sc integration collects and parses data from the [Tenable.sc](https://docs.tenable.com/tenablesc/Content/Welcome.htm) APIs.

## Compatibility

This module has been tested against `Tenable.sc version 5.18`

## Requirements

In order to ingest data from the Tenable.sc you must have the **Access key** and **Secret Key**.

Enable API keys to allow users to perform API key authentication. See: [Enable API Key Authentication]() in Tenable's documentation for more information. 

Generate API keys:
1. Log in to **Tenable.sc Admin account** via the user interface.
2. Click **Users > Users**.
3. In the row for the user for which you want to generate an API key, click the settings icon. It would open `actions menu`.
4. On the actions menu, click **Generate API Key**.
5. On the confirmation window, click **Generate**.
6. The "Your API Key" window appears, displaying the access key and secret key for the user.
7. Use the keys in the Tenable.sc Integration configuration parameters.

<DocCallOut title="Note">
The default value is the recommended value for a batch size by tenable. It can be found under _Advanced Options_ and can be configured as per requirements. A very large value might not work as intended depending on the API and instance limitations.
</DocCallOut>

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