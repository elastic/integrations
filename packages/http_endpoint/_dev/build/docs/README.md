# Custom HTTP Endpoint Log integration

The custom HTTP Endpoint Log package intializes a listening HTTP server that collects any incoming HTTP traffic in JSON format. For each HTTP packet it will create a new document to be stored in Elasticsearch.
Custom ingest pipelines may be added by adding the name to the pipeline configuration option, creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).
