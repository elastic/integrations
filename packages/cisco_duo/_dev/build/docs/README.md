# Cisco Duo

The Cisco Duo integration collects and parses data from the [Cisco Duo Admin APIs](https://duo.com/docs/adminapi).

## Compatibility

This module has been tested against Cisco Duo `Core Authentication Service: D224.13` and `Admin Panel: D224.18`

## Requirements

In order to ingest data from the Cisco Duo Admin API you must:
- Have a the Cisco Duo administrator account with **Owner** role [Sign up](https://signup.duo.com/)
- Sign in to [Duo Admin Panel](https://admin.duosecurity.com/)
- Go through following tabs **Application > Protect an Application > Admin API > Protect**
- Now you will find your **Hostname**, **Integration key** and **Secret key** which will be required while configuring the integration package.
- For this integration you will require **Grant read information** and **Grant read log** permissions.
- Make sure you have whitelisted your IP Address.

## Note

While setting up the interval take care of following.
- `Interval has to be greater than 1m.`
- `Larger values of interval might cause delay in data ingestion.`

## Logs

### Administrator

This is the `admin` dataset.

{{event "admin"}}

{{fields "admin"}}

### Authentication

This is the `auth` dataset.

{{event "auth"}}

{{fields "auth"}}

### Offline Enrollment

This is the `offline_enrollment` dataset.

{{event "offline_enrollment"}}

{{fields "offline_enrollment"}}

### Summary

This is the `summary` dataset.

{{event "summary"}}

{{fields "summary"}}

### Telephony

This is the `telephony` dataset.

{{event "telephony"}}

{{fields "telephony"}}