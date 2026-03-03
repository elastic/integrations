# Azure Application State Integration

The Application State Integration allows users to retrieve application insights state related metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Api Key`:: (_[]string_) The API key which will be generated, more on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/en-us/pricing/details/monitor/.

{{fields "app_state"}}







