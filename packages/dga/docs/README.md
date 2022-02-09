# ML Domain Generated Algorithm detection model

The DGA model package stores the Domain Generated Algorithm detection [model and associated assets] (https://www.elastic.co/guide/en/security/current/detection-engine-overview.html).
Requires a platinum license.

## Configuration

To download the assets in the **Security** app, click **Settings** > **Install DGA Model and assets**.
Ingest data with the installed ingest pipeline to enrich your indices with inference data and run the provided anomaly detection jobs.
For more information about activating the detection rules, refer to the [rules documentation] (https://www.elastic.co/guide/en/security/current/detection-engine-overview.html).

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
