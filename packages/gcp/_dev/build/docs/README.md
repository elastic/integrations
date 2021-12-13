# Google Cloud Platform Integration

This integration is used to fetches logs and metrics from 
[Google Cloud Platform](https://cloud.google.com/).

## GCP Credentials
GCP credentials are required for running GCP integration. 

### Configuration parameters
* *project_id*: ID of the GCP project.
* *credentials_file*: Path to JSON file with GCP credentials. Required when not using `credentials_json`.
* *credentials_json*: Raw JSON text of GCP Credentials. Required when not using `credentials_file`.
