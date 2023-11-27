# Living off the Land Attack Detection 

The Living off the Land Attack (LotL) Detection package contains a supervised machine learning model, called [ProblemChild and associated assets](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration), which are used to detect living off the land (LotL) activity in your environment. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license).

## v2.0.0 and beyond

v2.0.0 of the package introduces breaking changes, namely deprecating detection rules from the package. To continue receiving updates to LotL Detection, we recommend upgrading to v2.0.0 after doing the following:
- Uninstall existing rules associated with this package: Navigate to **Security > Rules** and delete the following rules:
    - Machine Learning Detected a Suspicious Windows Event Predicted to be Malicious Activity
    - Unusual Process Spawned By a Host
    - Suspicious Windows Process Cluster Spawned by a Host
    - Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score
    - Suspicious Windows Process Cluster Spawned by a Parent Process
    - Unusual Process Spawned By a User
    - Unusual Process Spawned By a Parent Process
    - Suspicious Windows Process Cluster Spawned by a User

Depending on the version of the package you're using, you might also be able to search for the above rules using the tag `Living off the Land`.
- Upgrade the LotL package to v2.0.0 using the steps [here](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html)
- Install the new rules as described in the [Enable detection rules](#enable-detection-rules) section below

In version 2.1.1, the package ignores data in cold and frozen data tiers to reduce heap memory usage, avoid running on outdated data, and to follow best practices.

## Configuration

To download the assets, click **Settings** > **Install Living off the Land Attack Detection assets**.

Follow these instructions to ingest data with the ingest pipeline and enrich your indices with inference data. Then use the anomaly detection jobs in this package and associated rules in the Detection Engine, to detect LotL attacks. For more detailed information refer to [this](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration) blog.

### Set up the ingest pipeline

Once you’ve installed the package you can ingest your data using the ingest pipeline. This will enrich your incoming data with its predictions from the machine learning model.

This pipeline is designed to work with Winlogbeat and Endpoint data.

### Add preconfigured anomaly detection jobs

Create a data view for the indices that are enriched by the pipeline.

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for `Living off the Land Attack Detection`. When you select the card, you will see several pre-configured anomaly detection jobs that you can enable depending on what makes the most sense for your environment. Note these jobs are only useful for indices that have been enriched by the ingest pipeline.

### Enable detection rules

You can also enable detection rules to alert on LotL activity in your environment, based on anomalies flagged by the above ML jobs. As of version 2.0.0 of this package, these rules are available as part of the Detection Engine, and can be found using the tag `Use Case: Living off the Land Attack Detection`. See this [documentation](https://www.elastic.co/guide/en/security/current/prebuilt-rules-management.html#load-prebuilt-rules) for more information on importing and enabling the rules.

## Anomaly Detection Jobs

Detects potential LotL activity by identifying malicious processes.

| Job | Description |
|---|---|
| problem_child_rare_process_by_host | Looks for a process that has been classified as malicious on a host that does not commonly manifest malicious process activity. |
| problem_child_high_sum_by_host | Looks for a set of one or more malicious child processes on a single host. |
| problem_child_rare_process_by_user | Looks for a process that has been classified as malicious where the user context is unusual and does not commonly manifest malicious process activity. |
| problem_child_rare_process_by_parent | Looks for rare malicious child processes spawned by a parent process. |
| problem_child_high_sum_by_user | Looks for a set of one or more malicious processes, started by the same user. |
| problem_child_high_sum_by_parent | Looks for a set of one or more malicious child processes spawned by the same parent process. |

## Licensing

Usage in production requires that you have a license key that permits use of machine learning features.