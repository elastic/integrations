# Custom API input integration

The custom API input integration is used to ingest data from custom RESTful API's that do not currently have an existing integration.

The input itself supports sending both GET and POST requests, transform requests and responses during runtime, paginate and keep a running state on information from the last collected events.

If you are starting development of a new custom HTTP API input, we recommend that you use the [Common Expression Language input](../cel/overview) which provides greater flexibility and an improved developer experience.

## Configuration

The extensive documentation for the input are currently available {{ url "filebeat-input-httpjson" "here" }}.

The most commonly used configuration options are available on the main integration page, while more advanced and customizable options currently resides under the "Advanced options" part of the integration settings page.

Configuration is split into three main categories, Request, Response, and Cursor.

The request part of the configuration handles points like which URL endpoint to communicate with, the request body, specific transformations that have to happen before a request is sent out and some custom options like request proxy, timeout and similar options.

The response part of the configuration handles options like transformation, rate limiting, pagination, and splitting the response into different documents before it is sent to Elasticsearch.

The cursor part of the configuration is used when there is a need to keep state between each of the API requests, for example if a timestamp is returned in the response, that should be used as a filter in the next request after that, the cursor is a place where this is stored.

