# Data Exfiltration Detection Model

The DED model package contains the data exfiltration detection model and the associated assets. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 1.0.

## Configuration

To download the assets, click **Settings** > **Install DED assets**.

Follow these instructions to ingest data with the ingest pipeline and enrich your indices with inference data. Then use these detection rules and anomaly detection jobs for data exfiltration detection.

### (Required) Set up the ingest pipeline

Once you’ve installed the package you can ingest your data using the ingest pipeline. This will enrich your incoming data with its predictions from the machine learning model.

### (Optional) Add preconfigured anomaly detection jobs

Create a data view for the indices that are enriched by the pipeline.

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for Data Exfiltration Detection (DED). When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment. Note this job is only useful for indices that have been enriched by the ingest pipeline.

## ML Modules

### DED

Detect data exfiltration activity in your network data.

| Job | Description |
|---|---|
| high-sent-bytes-destination-geo-city_name | A machine learning job to detect data exfiltration to a particular geo-location (by city name) | 
| high-sent-bytes-destination-geo-continent_name | A machine learning job to detect data exfiltration to a particular geo-location (by continent name) |
| high-sent-bytes-destination-geo-country_iso_code | A machine learning job to detect data exfiltration to a particular geo-location (by country iso code) |
| high-sent-bytes-destination-geo-country_name | A machine learning job to detect data exfiltration to a particular geo-location (by country name) |
| high-sent-bytes-destination-ip | A machine learning job to detect data exfiltration to a particular geo-location (by IP address) |
| high-sent-bytes-destination-port | A machine learning job to detect data exfiltration via a specific port |
| high-sent-bytes-destination-region_name | A machine learning job to detect data exfiltration to a particular geo-location (by region name) |
| high-sent-bytes-destination-timezone | A machine learning job to detect data exfiltration to a particular geo-location (by timezone) |

## Licensing
Usage in production requires that you have a license key that permits use of machine learning features.
