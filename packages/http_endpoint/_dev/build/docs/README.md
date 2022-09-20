# Custom HTTP Endpoint Log integration

The custom HTTP Endpoint Log integration initializes a listening HTTP server that collects incoming HTTP POST requests containing a JSON body. The body must be either an object or an array of objects. Any other data types will result in an HTTP 400 (Bad Request) response. For arrays, one document is created for each object in the array.

These are the possible response codes from the server.

| HTTP Response Code 	| Name                   	| Reason                                                             	|
|--------------------	|------------------------	|--------------------------------------------------------------------	|
| 200                	| OK                     	| Returned on success.                                               	|
| 400                	| Bad Request            	| Returned if JSON body decoding fails.                              	|
| 401                	| Unauthorized           	| Returned when basic auth, secret header, or HMAC validation fails. 	|
| 405                	| Method Not Allowed     	| Returned if methods other than POST are used.                      	|
| 406                	| Not Acceptable         	| Returned if the POST request does not contain a body.              	|
| 415                	| Unsupported Media Type 	| Returned if the Content-Type is not application/json.              	|
| 500                	| Internal Server Error  	| Returned if an I/O error occurs reading the request.               	|


Custom ingest pipelines may be added by adding the name to the pipeline configuration option, creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).
