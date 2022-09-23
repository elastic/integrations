# AWS API Gateway

The AWS API Gateway integration allows you to monitor [AWS API Gateway](https://aws.amazon.com/api-gateway)—a fully managed service that makes it easy for developers to create, publish, maintain, monitor, and secure APIs at any scale.

Use the AWS API Gateway integration to collect and parse logs related to API activity across your AWS infrastructure.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.

The API Gateway service includes 3 different types of gateways: REST API, HTTP API, and WebSocket API.

## Data streams

The AWS API Gateway integration collects one type of data: logs.

**Logs** help you keep a record of events happening in AWS API Gateway.
Logs collected by the AWS API Gateway integration include information the source of the request, the user, the related Labda function and more. See more details in the [Logs reference](#logs-reference).

> Note: The `api_gateway_logs` data stream is specifically for API Gateway logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS API Gateway service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
{{ url "getting-started-observability" "Getting started" }} guide.

The API Gateways can log both Access and Debug logs.  This integration is only configured to log Access logs and has not been tested with debug logging enabled.
Each gateway type has a multitude of variables that can be logged and different log formats that can be used. The integration expects JSON logs using the below formats/patterns.

[REST API](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats):  
`{"accountId":"$context.accountId","apiId":"$context.apiId","domainName":"$context.domainName","extendedRequestId":"$context.extendedRequestId","requestId":"$context.requestId","httpMethod":"$context.httpMethod","ip":"$context.identity.sourceIp","clientCertPem":"$context.identity.clientCert.clientCertPem","clientsubjectDN":"$context.identity.clientCert.subjectDN","clientissuerDN":"$context.identity.clientCert.issuerDN","clientserialNumber":"$context.identity.clientCert.serialNumber","clientnotBefore":"$context.identity.clientCert.validity.notBefore","clientnotAfter":"$context.identity.clientCert.validity.notAfter","user":"$context.identity.user","userAgent":"$context.identity.userAgent","userArn":"$context.identity.userArn","apiKeyId":"$context.identity.apiKeyId","protocol":"$context.protocol","requestTimeEpoch":"$context.requestTimeEpoch","path":"$context.path","status":"$context.status","responseLength":"$context.responseLength","stage":"$context.stage"}`

[HTTP API](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html#http-api-enable-logging.examples):  
`{"accountId":"$context.accountId","apiId":"$context.apiId","domainName":"$context.domainName","extendedRequestId":"$context.extendedRequestId","httpMethod":"$context.httpMethod","ip":"$context.identity.sourceIp","clientCertPem":"$context.identity.clientCert.clientCertPem","clientsubjectDN":"$context.identity.clientCert.subjectDN","clientissuerDN":"$context.identity.clientCert.issuerDN","clientserialNumber":"$context.identity.clientCert.serialNumber","clientnotBefore":"$context.identity.clientCert.validity.notBefore","clientnotAfter":"$context.identity.clientCert.validity.notAfter","user":"$context.identity.user","userAgent":"$context.identity.userAgent","userArn":"$context.identity.userArn","protocol":"$context.protocol","requestTimeEpoch":"$context.requestTimeEpoch","path":"$context.path","status":"$context.status","responseLength":"$context.responseLength","stage":"$context.stage"}`

[WebSocket API](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats):  
`{"apiId":"$context.apiId","eventType":"$context.eventType","domainName":"$context.domainName","extendedRequestId":"$context.extendedRequestId","requestId":"$context.requestId","ip":"$context.identity.sourceIp","user":"$context.identity.user","userAgent":"$context.identity.userAgent","userArn":"$context.identity.userArn","apiKeyId":"$context.identity.apiKeyId","requestTimeEpoch":"$context.requestTimeEpoch","status":"$context.status","stage":"$context.stage"}`
## Logs reference

The `api_gateway_logs` dataset is specifically for API Gateway logs. Export logs to Cloudwatch Logs.


{{fields "api_gateway_logs"}}

{{event "api_gateway_logs"}}