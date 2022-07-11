# M365 Defender integration

This integration is for M365 Defender logs, previously known as Threat Protection.

## Configuration

To configure access for Elastic Agent to communicate with Microsoft 365 Defender you will have to create a new Azure Application registration, this will again return OAuth tokens with access to the Microsoft 365 Defender API.

The procedure to create an application is found on the below link:

[Create a new Azure Application](https://docs.microsoft.com/en-us/microsoft-365/security/mtp/api-create-app-web?view=o365-worldwide#create-an-app)

When giving the application the API permissions described in the documentation (Incident.Read.All) it will only grant access to read Incidents from 365 Defender and nothing else in the Azure Domain.

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

{{event "log"}}

{{fields "log"}}
