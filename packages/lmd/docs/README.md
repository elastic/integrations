# Lateral Movement Detection Model

The Lateral movement detection model package contains the lateral movement detection model and the associated assets. This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 1.0.

## Configuration

To download the assets, click **Settings** > **Install Lateral Movement Detection assets**. 

Then use these detection rules and anomaly detection jobs for lateral movement detection.

### Add preconfigured anomaly detection jobs

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for Lateral Movement Detection. When you select the card, you will see a pre-configured anomaly detection job that you can enable depending on what makes the most sense for your environment.

### Enable Security rules

This model uses both anomaly detection and security rules to detect lateral movement in the network. To maximize the benefit of both frameworks, you should consider enabling the list of all "Security Detection Rules" described below. The first four rules are triggered when certain conditions for the anomaly detection jobs are satisfied. The last two rules are behavioral and independent of anomaly detection jobs. See the [documentation](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) for more information on importing and enabling the rules.

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

| Rule                                                                                                  | Description                                                                                                                                                                                                                        |
|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| High influx of remote file creations indicating a potential lateral movement activity                 | An anomaly detection job has detected an abnormal volume of remote files shared on the host indicating a potential lateral movement activity.                                                                                      |
| High size of remote file creations indicating a lateral movement activity                             | An anomaly detection job has detected an unusually high sum of file size shared by a remote host indicating a potential lateral movement activity.                                                                                 |
| Potential lateral tool transfer to an unusual directory                                               | An anomaly detection job has detected a remote file transfer on an unusual directory indicating a potential lateral movement activity on the host.                                                                                 |
| Potential lateral tool transfer having a rare extension                                               | An anomaly detection job has detected a remote file transfer with a rare extension indicating a potential lateral movement activity on the host.                                                                                   |
| Malicious remote file creation indicating a potential lateral tool transfer                           | Identifies the file created by a remote host followed by a malware or intrusion detection event triggered by Elastic Endpoint Security.                                                                                            |
| Suspicious remote file creation on a sensitive directory indicating a potential lateral tool transfer | Identifies the file created by a remote host on sensitive directories and folders. Remote file creation in these directories should not be common and could indicate a malicious binary or script trying to compromise the system. |                                                                           |

## Licensing
Usage in production requires that you have a license key that permits use of machine learning features.
