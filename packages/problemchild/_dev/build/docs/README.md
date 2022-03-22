# LotL Attack Detection 

The ProblemChild package contains the [ProblemChild model and associated assets](https://www.elastic.co/blog/problemchild-generate-alerts-to-detect-living-off-the-land-attacks), which are used to detect living off the land (LotL) activity.
This package requires a Platinum subscription. Please ensure that you have a Trial or Platinum level subscription installed on your cluster before proceeding. This package is licensed under Elastic License v 1.0.

## Configuration

To download the assets, click **Settings** > **Install LotL Attack Detection assets**.

Follow these instructions to ingest data with the ingest pipeline and enrich your indices with inference data. Then use these detection rules and anomaly detection jobs to detect LotL attacks. For more detailed information refer to the [ProblemChild blog](https://www.elastic.co/blog/problemchild-generate-alerts-to-detect-living-off-the-land-attacks)

### (Required) Set up the ingest pipeline

Once you’ve installed the package you can ingest your data using the ingest pipeline. This will enrich your incoming data with its predictions from the machine learning model.

This pipeline is designed to work with [Winglogbeat data](https://www.elastic.co/downloads/beats/winlogbeat).

### (Optional) Add preconfigured anomaly detection jobs

Create a data view for the indices that are enriched by the pipeline.

In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for LotL Attacks. When you select the card, you will see several pre-configured anomaly detection jobs that you can enable depending on what makes the most sense for your environment. Note these jobs are only useful for indices that have been enriched by the ingest pipeline.

### (Optional) Enable Security rules

In order to maximize the benefit of the LotL Detection framework, you might consider activating detection rules that are triggered when certain conditions for the supervised model or anomaly detection jobs are satisfied. See the [documentation](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) for more information on importing and enabling the rules.

Note that there are search rules as well as ML job rules.

## ML Modules

### ProblemChild

Detects potential living off the land activity by identifying malicious processes.

| Job | Description |
|---|---|
| problem_child_rare_process_by_host | Looks for a process that has been classified as malicious on a host that does not commonly manifest malicious process activity. This is an experimental job and is therefore unsupported. |
| problem_child_high_sum_by_host | Looks for a set of one or more malicious child processes on a single host. This is an experimental job and is therefore unsupported. |
| problem_child_rare_process_by_user | Looks for a process that has been classified as malicious where the user context is unusual and does not commonly manifest malicious process activity. This is an experimental job and is therefore unsupported.|
| problem_child_rare_process_by_parent | Looks for rare malicious child processes spawned by a parent process. This is an experimental job and is therefore unsupported. |
| problem_child_high_sum_by_user | Looks for a set of one or more malicious processes, started by the same user. This is an experimental job and is therefore unsupported. |
| problem_child_high_sum_by_parent | Looks for a set of one or more malicious child processes spawned by the same parent process. This is an experimental job and is therefore unsupported. |

## Security Detection Rules

| Rule | Description |
|---|---|
| Machine Learning Detected a Suspicious Windows Event Predicted to be Malicious Activity | A supervised machine learning model (ProblemChild) or its blocklist has identified a suspicious Windows process event to be malicious activity. |
| Unusual Process Spawned By a Host | A machine learning job has detected a suspicious Windows process. This process has been classified as malicious in two ways. It was predicted to be malicious by the ProblemChild supervised ML model, and it was found to be an unusual process, on a host that does not commonly manifest malicious activity. Such a process may be an instance of suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules. |
| Suspicious Windows Process Cluster Spawned by a Host | A machine learning job combination has detected a set of one or more suspicious Windows processes with unusually high scores for malicious probability. These process(es) have been classified as malicious in several ways. The process(es) were predicted to be malicious by the ProblemChild supervised ML model. If the anomaly contains a cluster of suspicious processes, each process has the same host name, and the aggregate score of the event cluster was calculated to be unusually high by an unsupervised ML model. Such a cluster often contains suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules. |
| Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score | A supervised machine learning model (ProblemChild) has identified a suspicious Windows process event with high probability of it being malicious activity. Alternatively, the model's blocklist identified the event as being malicious. |
| Suspicious Windows Process Cluster Spawned by a Parent Process | A machine learning job combination has detected a set of one or more suspicious Windows processes with unusually high scores for malicious probability. These process(es) have been classified as malicious in several ways. The process(es) were predicted to be malicious by the ProblemChild supervised ML model. If the anomaly contains a cluster of suspicious processes, each process has the same parent process name, and the aggregate score of the event cluster was calculated to be unusually high by an unsupervised ML model. Such a cluster often contains suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules. |
| Unusual Process Spawned By a User | A machine learning job has detected a suspicious Windows process. This process has been classified as malicious in two ways. It was predicted to be malicious by the ProblemChild supervised ML model, and it was found to be suspicious given that its user context is unusual and does not commonly manifest malicious activity,by an unsupervised ML model. Such a process may be an instance of suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules. |
| Unusual Process Spawned By a Parent Process | A machine learning job has detected a suspicious Windows process. This process has been classified as malicious in two ways. It was predicted to be malicious by the ProblemChild supervised ML model, and it was found to be an unusual child process name, for the parent process, by an unsupervised ML model. Such a process may be an instance of suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules. |
| Suspicious Windows Process Cluster Spawned by a User | A machine learning job combination has detected a set of one or more suspicious Windows processes with unusually high scores for malicious probability. These process(es) have been classified as malicious in several ways. The process(es) were predicted to be malicious by the ProblemChild supervised ML model. If the anomaly contains a cluster of suspicious processes, each process has the same user name, and the aggregate score of the event cluster was calculated to be unusually high by an unsupervised ML model. Such a cluster often contains suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules. |

## Licensing
Usage in production requires that you have a license key that permits use of machine learning features.