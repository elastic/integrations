# Data Exfiltration Detection

The Data Exfiltration Detection (DED) package contains assets for detecting data exfiltration in network data. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 2.0.

## Configuration

To download the assets, click **Settings** > **Install Data Exfiltration Detection assets**. 

Then use these detection rules and anomaly detection jobs for data exfiltration detection.

### Add preconfigured anomaly detection jobs

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for Data Exfiltration Detection. When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment.

### (Optional) Enable Security rules

To maximize the benefit of the Data Exfiltration Detection detection framework, activate the detection rules that are triggered when certain conditions for the anomaly detection jobs are satisfied. See the [documentation](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) for more information on importing and enabling the rules.

### Anomaly Detection Jobs

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
| Potential Data Exfiltration Activity to an Unusual City | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual city.|
| Potential Data Exfiltration Activity to an Unusual Country | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual country.|
| Potential Data Exfiltration Activity to an Unusual ISO Code | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual country by its iso code.|
| Potential Data Exfiltration Activity to an Unusual Region | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual region name.|
| Potential Data Exfiltration Activity to an Unusual Continent | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual continent.|
| Potential Data Exfiltration Activity to an Unusual Timezone | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual timezone.|
| Potential Data Exfiltration Activity to an Unusual IP Address | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual IP address.|
| Potential Data Exfiltration Activity to an Unusual Destination Port | An anomaly detection job has detected an abnormal volume of bytes being sent to an unusual destination port.|

## Dashboard

The **Data Exfiltration Detection Dashboard** is available under **Analytics > Dashboard**. This dashboard gives an overview of anomalies triggered for the data exfiltration detection package.

For the dashboard to work as expected, the following settings need to be configured in Kibana. 
1. You have started the above anomaly detection jobs.
2. You have **read** access to **.ml-anomalies-shared** index or are assigned the **machine_learning_user** role. For more information on roles, please refer to [Built-in roles in Elastic](https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-roles.html). Please be aware that a user who has access to the underlying machine learning results indices can see the results of _all_ jobs in _all_ spaces. Be mindful of granting permissions if you use Kibana spaces to control which users can see which machine learning results. For more information on machine learning privileges, refer to [setup-privileges](https://www.elastic.co/guide/en/machine-learning/current/setup.html#setup-privileges).
3. After enabling the jobs, go to **Management > Stack Management > Kibana > Data Views**. 
4. Click on **Create data view** button and enable **Allow hidden and system indices** under the **Show Advanced settings**.
5. Create a data view with the following settings:
    - Index pattern : `.ml-anomalies-shared`
    - Name: `.ml-anomalies-shared`
    - Custom data view ID: `.ml-anomalies-shared`
## Licensing
Usage in production requires that you have a license key that permits use of machine learning features.
