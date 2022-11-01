# Data Exfiltration Detection (DED) Model

The DED model package contains the data exfiltration detection model and the associated assets. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 1.0.

## Configuration

To download the assets, click **Settings** > **Install DED assets**. 

Then use these detection rules and anomaly detection jobs for data exfiltration detection.

### Add preconfigured anomaly detection jobs

Create a data view for the indices that are enriched by the pipeline.

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for Data Exfiltration Detection (DED). When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment.

### (Optional) Enable Security rules

In order to maximize the benefit of the DED detection framework, you might consider activating detection rules that are triggered when certain conditions for the anomaly detection jobs are satisfied.

## ML Modules

### DED

Detect data exfiltration activity in your network data.

| Job | Description |
|---|---|
| high-sent-bytes-destination-geo-city_name | A machine learning job to detect data exfiltration to an unusual geo-location (by city name) | 
| high-sent-bytes-destination-geo-continent_name | A machine learning job to detect data exfiltration to an unusual geo-location (by continent name) |
| high-sent-bytes-destination-geo-country_iso_code | A machine learning job to detect data exfiltration to an unusual geo-location (by country iso code) |
| high-sent-bytes-destination-geo-country_name | A machine learning job to detect data exfiltration to an unusual geo-location (by country name) |
| high-sent-bytes-destination-ip | A machine learning job to detect data exfiltration to an unusual geo-location (by IP address) |
| high-sent-bytes-destination-port | A machine learning job to detect data exfiltration to an unusual destination port |
| high-sent-bytes-destination-region_name | A machine learning job to detect data exfiltration to an unusual geo-location (by region name) |
| high-sent-bytes-destination-timezone | A machine learning job to detect data exfiltration to an unusual geo-location (by timezone) |

## Security Detection Rules

| Rule | Description |
|---|---|
| DED activity detection to an unusal city | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual city.|
| DED activity detection to an unusal country | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual country.|
| DED activity detection to an unusal country by its iso code | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual country by its iso code.|
| DED activity detection to an unusal region name | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual region name.|
| DED activity detection to an unusal continent | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual continent.|
| DED activity detection to an unusal timezone | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual timezone.|
| DED activity detection to an unusal IP address | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual IP address.|
| DED activity detection to an unusal destination port | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual destination port.|

## Licensing
Usage in production requires that you have a license key that permits use of machine learning features.
