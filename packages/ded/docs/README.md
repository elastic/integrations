# Data Exfiltration Detection

The Data Exfiltration Detection (DED) package contains assets for detecting data exfiltration in network and file data. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 2.0.


**_Note_**: v2.0.0 of the package introduces breaking changes, namely updating ML job IDs and deprecating detection rules from the package. To continue recieving updates to Lateral Movement Detection, we recommend uninstalling existing ML jobs and rules associated with this package, upgrading to v2.0.0, and installing the new rules as described in the [Enabling detection rules](#enable-detection-rules) section below.


## Configuration

To download the assets, click **Settings** > **Install Data Exfiltration Detection assets**. 

Then use the anomaly detection jobs from this package and associated rules from the Detection Engine, to detect Data Exfiltration.

### Add preconfigured anomaly detection jobs

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for **Data Exfiltration Detection**. When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment.

**_Note_**: In the Machine Learning app, these configurations are available only when data exists that matches the query specified in the [ded-ml file](https://github.com/elastic/integrations/blob/main/packages/ded/kibana/ml_module/ded-ml.json#L10).

### Enable detection rules

You can also enable detection rules to alert on Data Exfiltration activity in your environment, based on anomalies flagged by the above ML jobs. As of version 2.0.0 of this package, these rules are available as part of the Detection Engine, and can be found using the tag `Use Case: Data Exfiltration Detection`. See this [documentation](https://www.elastic.co/guide/en/security/current/prebuilt-rules-management.html#load-prebuilt-rules) for more information on importing and enabling the rules.

### Anomaly Detection Jobs

| Job | Description                                                                                |
|---|--------------------------------------------------------------------------------------------|
| ded_high_sent_bytes_destination_geo_country_iso_code | Detects data exfiltration to an unusual geo-location (by country iso code).                |
| ded_high_sent_bytes_destination_ip | Detects data exfiltration to an unusual geo-location (by IP address).                      |
| ded_high_sent_bytes_destination_port | Detects data exfiltration to an unusual destination port.                                  |
| ded_high_sent_bytes_destination_region_name | Detects data exfiltration to an unusual geo-location (by region name).                     |
 | ded_high_bytes_written_to_external_device | Detects data exfiltration activity by identifying high bytes written to an external device. |
 | ded_rare_process_writing_to_external_device | Detects data exfiltration activity by identifying a writing event started by a rare process to an external device. |
 | ded_high_bytes_written_to_external_device_airdrop | Detects data exfiltration activity by identifying high bytes written to an external device via Airdrop.|


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

