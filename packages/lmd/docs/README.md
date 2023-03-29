# Lateral Movement Detection Model

The Lateral movement detection model package contains assets that detect lateral movement based on file transfer activity. This package requires a Platinum subscription. Please ensure that you have a Trial, Platinum, or Enterprise subscription before proceeding. This package is licensed under Elastic License v 2.0.

## Configuration

To download the assets, click **Settings** > **Install Lateral Movement Detection assets**. 


### Add preconfigured anomaly detection jobs

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for Lateral Movement Detection. When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment.

### Enable Security rules

This model uses both anomaly detection and security rules to detect lateral movement in the network. In order to see all alerts detected by this model, you need to enable all the "Security Detection Rules" in the table, as described below. The first four rules are triggered when certain conditions for the anomaly detection jobs are satisfied. The last two rules are behavioral and independent of anomaly detection jobs. See the [documentation](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) for more information on importing and enabling the rules.

## ML Modules

### Lateral Movement Detection 

Detects potential lateral movement activity by identifying malicious file transfers to a host.

| Job | Description                                                                                                 |
|---|-------------------------------------------------------------------------------------------------------------|
| high-count-remote-file-transfer | A machine learning job to detect unusually high file transfers to a remote host in the network              | 
| high-file-size-remote-file-transfer | A machine learning job to detect unusually high size of files shared with a remote host in the network      |
| rare-file-extension-remote-transfer | A machine learning job to detect rare file extensions shared with a remote host in the network              |
| rare-file-path-remote-transfer | A machine learning job to detect unusual folders and directories on which a file is transferred (by a host) |


## Security Detection Rules

| Rule                                          | Description                                                                                                                                                                                                                        |
|-----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Spike in Remote File Transfers                | An anomaly detection job has detected an abnormal volume of remote files shared on the host indicating a potential lateral movement activity.                                                                                      |
| Unusual Remote File Size                      | An anomaly detection job has detected an unusually high sum of file size shared by a remote host indicating a potential lateral movement activity.                                                                                 |
| Unusual Remote File Directory                 | An anomaly detection job has detected a remote file transfer on an unusual directory indicating a potential lateral movement activity on the host.                                                                                 |
| Unusual Remote File Extension                 | An anomaly detection job has detected a remote file transfer with a rare extension indicating a potential lateral movement activity on the host.                                                                                   |
| Malicious Remote File Creation                | Identifies the file created by a remote host followed by a malware or intrusion detection event triggered by Elastic Endpoint Security.                                                                                            |
| Remote File Creation on a Sensitive Directory | Identifies the file created by a remote host on sensitive directories and folders. Remote file creation in these directories should not be common and could indicate a malicious binary or script trying to compromise the system. |                                                                           |

## Dashboard

The **Lateral Movement Detection Dashboard** is available under **Analytics > Dashboard**. This dashboard gives an overview of anomalies triggered for the lateral movement detection package.

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
