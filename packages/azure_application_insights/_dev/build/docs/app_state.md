# Azure Application State Integration

The Application State Integration allows users to retrieve application insights state related metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Authentication Type`:: (_string_) Optional. The authentication method to use. Accepted values: `api_key` or `client_secret`. Defaults to `client_secret` if not set.

`Api Key`:: (_string_) Optional. The API key used for authentication when `auth_type` is set to `api_key`. More on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.

`Client ID`:: (_string_) Optional. The client (application) ID of the Entra ID application. Required when `auth_type` is `client_secret`.

`Client Secret`:: (_string_) Optional. The client secret of the Entra ID application. Required when `auth_type` is `client_secret`.

`Tenant ID`:: (_string_) Optional. The tenant (directory) ID of the Entra ID tenant. Required when `auth_type` is `client_secret`.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/en-us/pricing/details/monitor/.

{{fields "app_state"}}







