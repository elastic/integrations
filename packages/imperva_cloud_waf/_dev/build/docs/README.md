# Imperva Cloud WAF

Imperva Cloud WAF is a cloud-based application delivery service that includes web security, DDoS protection, CDN, and load balancing.

## Data streams

This integration supports ingestion of events from Imperva Cloud WAF, via AWS S3 input or via [Imperva API](https://docs.imperva.com/bundle/cloud-application-security/page/settings/log-integration.htm).

**Event** is used to retrieve access and security events. See more details in the documentation [here](https://docs.imperva.com/bundle/cloud-application-security/page/more/log-file-structure.htm).

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).  

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### Steps to setup Amazon S3 Connection(Push Mode):

1. Login to your [Imperva Cloud WAF console](https://authentication-management.service.imperva.com/login).
2. On the sidebar, click Logs > Log Setup.
3. Connection. Select **Amazon S3**.
4. Next, fill in your credentials:  
   Your S3 Access key, Secret key, and Path, where path is the location of the folder where you want to store the logs. Enter the path in the following format: <Amazon S3 bucket name>/<log folder>. For example: MyBucket/MyIncapsulaLogFolder.
5. Click Test connection to perform a full testing cycle in which a test file will be transferred to your designated folder. The test file does not contain real data, and will be removed by Incapsula when the transfer is complete.
6. Configure the additional options:
    - Format. Select the format for the log files: CEF
    - Compress logs. By default, log files are compressed. Clear this option to keep the logs uncompressed.

### Steps to obtain API URL, API Key and API ID(Pull Mode):

1. Login to your [Imperva Cloud WAF console](https://authentication-management.service.imperva.com/login).
2. On the sidebar, click Logs > Log Setup.
3. Connection. Select **Imperva API**.
4. From this window copy and keep API Key handy, this will be required for further Integration configuration.
5. Copy **API ID** and **Log Server URI**.
6. Configure the additional options:
    - Format. Select the format for the log files: CEF
    - Compress logs. By default, log files are compressed. Clear this option to keep the logs uncompressed.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Imperva Cloud WAF
3. Click on the "Imperva Cloud WAF" integration from the search results.
4. Click on the "Add Imperva Cloud WAF" button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, keep **Collect Imperva Cloud WAF logs via AWS S3 or AWS SQS** toggle on and then configure following parameters:
   - access key id
   - secret access key
   - bucket arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, keep **Collect Imperva Cloud WAF logs via AWS S3 or AWS SQS** toggle on and then configure following parameters:
   - access key id
   - secret access key
   - queue url
   - collect logs via S3 Bucket toggled off

   or if you want to collect logs via API, keep **Collect Imperva Cloud WAF logs via API** toggle on and and then configure following parameters:
   - API ID
   - API Key
   - URL
6. Save the integration.

**NOTE**: There are other input combination options available for AWS S3 input, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs Reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
