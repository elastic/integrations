# Inspector

The [AWS Inspector](https://docs.aws.amazon.com/inspector/) integration collects and parses data from AWS Inspector [Findings](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html) REST APIs.

## Compatibility

  1. The minimum compatible version of this module is **Elastic Agent 8.4.0**.
  2. This module is tested against `AWS Inspector API version 2.0`.

## To collect data from AWS Inspector API, users must have an Access Key and a Secret Key. To create API token follow below steps:

  1. Login to https://console.aws.amazon.com/.
  2. Go to https://console.aws.amazon.com/iam/ to access the IAM console.
  3. On the navigation menu, choose Users.
  4. Choose your IAM user name.
  5. Select Create access key from the Security Credentials tab.
  6. To see the new access key, choose Show.

## Note

  - For the current integration package, it is compulsory to add Secret Access Key and Access Key ID.

## Logs

### Inspector

This is the [`Inspector`](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html#inspector2-ListFindings-response-findings) data stream.

{{event "inspector"}}

{{fields "inspector"}}