# LeakData Exposure Monitoring integration

Bring verified breach-exposure alerts into Elastic Security without copying the underlying personal data into your SIEM. Elastic Agent collects alerts from LeakData and maps them to Elastic Common Schema (ECS).

Each alert provides a severity, a finding count, an event ID and timestamps. Use these signals to prioritize an investigation in LeakData alongside your other security telemetry. An exposure alert does not establish that an account has been compromised.

## Requirements

- Elastic Stack 9.3.1 or later within the supported 9.x range, with Fleet and Elastic Agent.
- An active LeakData account with SIEM integration access.
- A personal-email monitor with confirmed ownership and monitoring enabled.

Your LeakData plan and Elastic deployment requirements apply separately. [Explore LeakData](https://leakdata.io/integrations/elastic-security) or [view plans](https://leakdata.io/pricing).

## Data and verification boundary

LeakData releases an alert only when an active personal-email monitor still has exact ownership verification, every represented source remains verified at the configured `high` or `critical` threshold, and the account still has the SIEM integration entitlement.

The feed does not include an email address, monitor identifier, breach/source name, source URL, credential, password, exposed value, raw record, or `event.original`.

## Setup

1. In the LeakData dashboard, create an Elastic Security connector and choose the exposure threshold you want to monitor.
2. Copy the connector token when it is shown. You will use it to connect Elastic Agent.
3. Add this integration to a Fleet agent policy. Keep the default LeakData URL and paste the token into **Connector token**. Fleet stores this setting as a secret.
4. Leave the poll interval at five minutes, or adjust it to suit your workflow. Keep the `forwarded` tag; you can add your own tags.
5. After LeakData detects a new eligible exposure, use Discover to check `logs-leakdata.exposure-*` for the alert.

An empty feed can be expected when there are no new eligible alerts. Check that the monitor is active, its email ownership remains verified and your account still has SIEM integration access before investigating the connection.

## Logs reference

### exposure

{{event "exposure"}}

{{fields "exposure"}}

Version `0.1.0` is a submission candidate and is not represented as Elastic-reviewed or published.

For setup and account questions, contact [support@leakdata.io](mailto:support@leakdata.io). Report security issues privately to [security@leakdata.io](mailto:security@leakdata.io).
