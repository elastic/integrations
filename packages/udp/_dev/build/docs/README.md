# Custom UDP Log integration

The custom UDP Log package intialize a listening UDP socket that collects any UDP traffic received and sends each line as a document to Elasticsearch.
Custom ingest pipelines may be added by adding the name to the pipeline configuration option, creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).
