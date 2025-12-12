# AWS Security Hub Integration for Elastic

## Overview
The AWS Security Hub integration with Elastic enables the collection of findings for monitoring and analysis. This valuable data can be leveraged within Elastic to analyze security signals from multiple sources, such as posture management, vulnerability management (Amazon Inspector), sensitive data identification (Amazon Macie), and threat detection (Amazon GuardDuty).

This integration utilizes the AWS Security Hub API to collect Findings in the OCSF format.

### Compatibility

The AWS Security Hub integration uses the REST API. It uses the `GetFindingsV2` to collect findings in OCSF format.

### How it works

The **finding** data stream uses the `/findingsv2` endpoint to gather all findings starting from the configured `Initial Interval`. Subsequently, it fetches the recent findings available at each specified `Interval`.

## What data does this integration collect?

The AWS Security Hub integration collects logs of the following types:

- `Finding`: Returns a list of findings in OCSF format. Refer to the [GetFindingsV2 API Reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingsV2.html).

### Supported use cases

Integrating AWS Security Hub with Elastic SIEM provides a comprehensive view of the security state of your AWS resources. Leveraging AWS Security Hub integration helps you analyze security trends to identify and prioritize security issues across your AWS environment. It also adds support for the [Elastic Cloud Security Workflow](https://www.elastic.co/docs/solutions/security/cloud/ingest-third-party-cloud-security-data#_ingest_third_party_security_posture_and_vulnerability_data), allowing users to explore insights via the Elastic [Vulnerability Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page-3).

## What do I need to use this integration?

### From Elastic

AWS Security Hub integration adds [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From AWS Security Hub

Enable AWS Security Hub in your environment. For more detail, refer to the link [here](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-enable.html).

#### Collecting data from AWS Security Hub API

Users can authenticate using permanent security credentials, as well as temporary security credentials. They can also select `Shared Credential File`, `Credential Profile Name` to retrieve credentials. Additionally, they can use `Role ARN` to specify which AWS IAM role to assume for generating temporary credentials. An `External ID` can also be provided when assuming a role in another account.

The credentials must have permission to perform the **securityhub:GetFindings** action.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html) 

### Onboard / configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **AWS Security Hub**.
3. Select the **AWS Security Hub** integration from the search results.
4. Select **Add AWS Security Hub** to add the integration.
5. Enable and configure **Collect AWS Security Hub logs via API**:

    - Configure AWS Authentication parameters and set the **AWS Region** and **Top Level Domain**. Adjust the integration configuration parameters as needed, including the **Initial Interval**, **Interval**, **Batch Size** etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **AWS Security Hub**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **aws_securityhub**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Finding

{{fields "finding"}}

### Example event

#### Finding

{{event "finding"}}

### Inputs used

These inputs are used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following APIs:

- `Finding`: [AWS Security Hub REST API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingsV2.html).
