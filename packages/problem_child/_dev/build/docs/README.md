# ProblemChild Detection Model

The ProblemChild package contains the [ProblemChild model and associated assets](https://www.elastic.co/blog/problemchild-generate-alerts-to-detect-living-off-the-land-attacks), which are used to detect living off the land (LotL) activity.
Requires a platinum license.

## Configuration

To download the assets in the **Security** app, click **Settings** > **Install ProblemChild assets**.
Ingest data with the installed ingest pipeline to enrich your indices with inference data and run the provided anomaly detection jobs.
For more information about activating the detection rules, refer to the [rules documentation] (https://www.elastic.co/guide/en/security/current/detection-engine-overview.html).


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