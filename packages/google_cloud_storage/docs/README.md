# Custom GCS (Google Cloud Storage) Input

Use the `Google Cloud Storage input` to read content from files stored in buckets that reside on your Google Cloud.
The input can be configured to work with and without polling, though currently, if polling is disabled it will only 
perform a one-time passthrough, list the file contents and end the process. Polling is generally recommended for most cases
even though it can get expensive with dealing with a very large number of files.

*To mitigate errors and ensure a stable processing environment, this input employs the following features :* 

1.  When processing Google Cloud buckets, if suddenly there is any outage, the process will be able to resume post the last file it processed and for which it was successfully able to save the state. 

2.  If any errors occur for certain files, they will be logged appropriately, but the rest of the files will continue to be processed normally. 

3.  If any major error occurs that stops the main thread, the logs will be appropriately generated, describing said error.


NOTE: Currently only `JSON` is supported with respect to object/file formats. We also support gzipped JSON objects/files. As for authentication types, we currently have support for `JSON credential keys` and `credential files`. If a download for a file/object fails or gets interrupted, the download is retried two times which equates to a maximum of three tries for a particular file/object. This is behavior currently not user-configurable.

## The GCS credentials key file:
This is a one-time download JSON key file that you get after adding a key to a GCP service account. 
If you are just starting out creating your GCS bucket, do the following: 

1) Make sure you have a service account available, if not follow the steps below:
   - Navigate to 'APIs & Services' > 'Credentials'
   - Click on 'Create credentials' > 'Service account'
2) Once the service account is created, you can navigate to the 'Keys' section and attach/generate your service account key.
3) Make sure to download the JSON key file once prompted.
4) Use this JSON key file either inline (JSON string object), or by specifying the path to the file on the host machine, where the agent is running.

A sample JSON Credentials file looks as follows: 
```json
{
  "type": "dummy_service_account",
  "project_id": "dummy-project",
  "private_key_id": "dummy-private-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nDummyPrivateKey\n-----END PRIVATE KEY-----\n",
  "client_email": "dummy-service-account@example.com",
  "client_id": "12345678901234567890",
  "auth_uri": "https://dummy-auth-uri.com",
  "token_uri": "https://dummy-token-uri.com",
  "auth_provider_x509_cert_url": "https://dummy-auth-provider-cert-url.com",
  "client_x509_cert_url": "https://dummy-client-cert-url.com",
  "universe_domain": "dummy-universe-domain.com"
}
```

**NOTE**:
- When using the GCS integration, if you are using JSON Credentials inline, then you must specify the entire JSON object within single quotes i.e `'{GCS_CREDS_JSON_OBJECT}'`

# Configuring The Input: 
Assuming you have GCS buckets already set up and the service account key available, please refer to the input documentation [here](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-input-gcs.html) for further details on specific parameters used by the integration.

## ECS Field Mapping
This integration includes the ECS Dynamic Template, all fields that follow the ECS Schema will get assigned the correct index field mapping and do not need to be added manually.

## Ingest Pipelines
Custom ingest pipelines may be added by adding the name to the pipeline configuration option, creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).
