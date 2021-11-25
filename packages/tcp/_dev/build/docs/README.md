# Custom TCP Log integration

The custom TCP Log package intializes a listening TCP socket that collects any TCP traffic received and sends each line as a document to Elasticsearch.
Custom ingest pipelines may be added by adding the name to the pipeline configuration option, creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).
