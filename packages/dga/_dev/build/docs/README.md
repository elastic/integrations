# ML Domain Generated Algorithm detection model

The DGA model package stores the Domain Generated Algorithm detection model and associated assets.
This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 1.0.

## Configuration

To download the assets, click **Settings** > **Install DGA assets**.

Follow these instructions to ingest data with the ingest pipeline and enrich your indices with inference data. Then use these detection rules and anomaly detection jobs for Domain Generated Algorithm detection. For more detailed information refer to the [DGA blog](https://www.elastic.co/blog/supervised-and-unsupervised-machine-learning-for-dga-detection)

### (Required) Set up the ingest pipeline

Once you’ve installed the package you can ingest your data using the ingest pipeline. This will enrich your incoming data with its predictions from the machine learning model.

### (Optional) Add preconfigured anomaly detection jobs

Create a data view for the indices that are enriched by the pipeline.

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for Domain Generated Algorithm (DGA) detection. When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment. Note this job is only useful for indices that have been enriched by the ingest pipeline.

### (Optional) Enable Security rules

In order to maximize the benefit of the DGA detection framework, you might consider activating detection rules that are triggered when certain conditions for the supervised model or anomaly detection jobs are satisfied. See the [documentation](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) for more information on importing and enabling the rules.

Note that there are search rules as well as ML job rules.

## ML Modules

### DGA

Detect domain generation algorithm (DGA) activity in your network data.

| Job | Description |
|---|---|
| dga_high_sum_probability | Detects potential DGA (domain generation algorithm) activity that is often used by malware command and control (C2) channels. Looks for a source IP address making DNS requests that have an aggregate high probability of being DGA activity (experimental).| 

## Security Detection Rules

| Rule | Description |
|---|---|
| Machine Learning Detected DGA activity using a known SUNBURST DNS domain | A supervised machine learning model has identified a DNS question name that used by the SUNBURST malware and is predicted to be the result of a Domain Generation Algorithm.|
| Machine Learning Detected a DNS Request Predicted to be a DGA Domain | A supervised machine learning model has identified a DNS question name that is predicted to be the result of a Domain Generation Algorithm (DGA), which could indicate command and control network activity.|
| Potential DGA Activity | A population analysis machine learning job detected potential DGA (domain generation algorithm) activity. Such activity is often used by malware command and control (C2) channels. This machine learning job looks for a source IP address making DNS requests that have an aggregate high probability of being DGA activity. This is an experimental job and is therefore unsupported.|
| Machine Learning Detected a DNS Request With a High DGA Probability Score | A supervised machine learning model has identified a DNS question name with a high probability of sourcing from a Domain Generation Algorithm (DGA), which could indicate command and control network activity.|

## Licensing
Usage in production requires that you have a license key that permits use of machine learning features.
