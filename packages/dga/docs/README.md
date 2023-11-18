# Domain Generated Algorithm Detection

The Domain Generated Algorithm (DGA) Detection package contains assets to detect DGA activity in your network data. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license).

## v2.0.0 and beyond

v2.0.0 of the package introduces breaking changes, namely deprecating detection rules from the package. To continue receiving updates to DGA Detection, we recommend upgrading to v2.0.0 after doing the following:
- Uninstall existing rules associated with this package: Navigate to **Security > Rules** and delete the following rules:
    - Machine Learning Detected DGA activity using a known SUNBURST DNS domain
    - Machine Learning Detected a DNS Request Predicted to be a DGA Domain
    - Potential DGA Activity
    - Machine Learning Detected a DNS Request With a High DGA Probability Score

Depending on the version of the package you're using, you might also be able to search for the above rules using the tag `DGA`
- Upgrade the DGA package to v2.0.0 using the steps [here](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html)
- Install the new rules as described in the [Enable detection rules](#enable-detection-rules) section below

In version 2.0.1, the package ignores data in cold and frozen data tiers to reduce heap memory usage, avoid running on outdated data, and to follow best practices.

## Configuration

To download the assets, click **Settings** > **Install Domain Generated Algorithm Detection assets**.

Follow these instructions to ingest data with the ingest pipeline and enrich your indices with inference data. Then use the anomaly detection jobs in this package and associated rules in the Detection Engine, for Domain Generated Algorithm detection. For more detailed information refer to the [DGA blog](https://www.elastic.co/blog/supervised-and-unsupervised-machine-learning-for-dga-detection)

### Set up the ingest pipeline

Once you’ve installed the package you can ingest your data using the ingest pipeline. This will enrich your incoming data with its predictions from the machine learning model.

### Add preconfigured anomaly detection jobs

Create a data view for the indices that are enriched by the pipeline.

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for `DGA`. When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment. Note this job is only useful for indices that have been enriched by the ingest pipeline.

### Enable detection rules

You can also enable detection rules to alert on DGA activity in your environment, based on anomalies flagged by the above ML jobs. As of version 2.0.0 of this package, these rules are available as part of the Detection Engine, and can be found using the tag `Use Case: Domain Generated Algorithm Detection`. See this [documentation](https://www.elastic.co/guide/en/security/current/prebuilt-rules-management.html#load-prebuilt-rules) for more information on importing and enabling the rules.

## Anomaly Detection Jobs

| Job | Description |
|---|---|
| dga_high_sum_probability | Detects potential DGA (domain generation algorithm) activity that is often used by malware command and control (C2) channels. Looks for a source IP address making DNS requests that have an aggregate high probability of being DGA activity.| 

## Licensing

Usage in production requires that you have a license key that permits use of machine learning features.
