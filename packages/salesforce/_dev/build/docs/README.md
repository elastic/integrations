# Salesforce Integration

## Overview

The Salesforce integration allows you to monitor [Salesforce](https://www.salesforce.com/) instance. Salesforce provides customer relationship management service and also provides enterprise applications focused on customer service, marketing automation, analytics, and application development.

Use the Salesforce integration to get visibility into the Salesforce Org operations and hold Salesforce accountable to the Service Level Agreements. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, if you want to check the number of successful and failed login attempts over time, you could check the same based on the ingested events or the visualization. Then you can create visualizations, alerts and troubleshoot by looking at the documents ingested in Elasticsearch.

## Data streams

The Salesforce integration collects log events using REST and Streaming API of Salesforce.

**Logs** help you keep a record of events happening in Salesforce.
Log data streams collected by the Salesforce integration include [Login](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm) (using REST and Streaming API), [Logout](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm) (using REST and Streaming API), [Apex](https://developer.salesforce.com/docs/atlas.en-us.238.0.object_reference.meta/object_reference/sforce_api_objects_apexclass.htm), and [SetupAuditTrail](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm).

Data stream names:
- `login_rest`
- `logout_rest`
- `apex`
- `setupaudittrail`
- `login_stream`
- `logout_stream`

## Compatibility

This integration has been tested against Salesforce `Spring '22 (v54.0) release`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### Steps to find out the version of Salesforce

On the Home tab in Salesforce Classic, on the top right of the screen is a link to release like `Summer '22`. This indicates your release.

Another alternative to find out the version of Salesforce is hitting the following URL:
- Format: (Salesforce Instance URL)/services/data
- Example: https://elastic1234-dev-ed.my.salesforce.com/services/data

Example response:
```xml
<Versions>
	<Version>
		<label>Winter '22</label>
		<url>/services/data/v53.0</url>
		<version>53.0</version>
	</Version>
	<Version>
		<label>Spring '22</label>
		<url>/services/data/v54.0</url>
		<version>54.0</version>
	</Version>
	<Version>
		<label>Summer '22</label>
		<url>/services/data/v55.0</url>
		<version>55.0</version>
	</Version>
</Versions>
```
The last one in the list is the release of your instance. In the example above, the version is `Summer '22` i.e. `v55.0`.

### Steps to find out the API version

- Go to `Setup` > `Quick Find` > `Apex` > `Apex Classes`
- Then, click `New` button
- Then, click over to `Version Settings` tab
- Reference the `Version` drop down for the API Version number.

### Prerequisite

In order to use this integration, you will need to create a new SFDC Application using OAuth. More details can be found [here](https://help.salesforce.com/apex/HTViewHelpDoc?id=connected_app_create.htm).

Create a Connected App in Salesforce:

1. Login to [Salesforce](https://login.salesforce.com/) with the same user credentials that you want to collect data.

2. From Setup, enter "App Manager" in the Quick Find box, then select "App Manager".

3. Click *New Connected App*.

4. Enter the connected app's name, which displays in the App Manager and on its App Launcher tile.

5. Enter the API name. The default is a version of the name without spaces. Only letters, numbers, and underscores are allowed. If the original app name contains any other characters, edit the default name.

6. Enter the contact email for Salesforce.

7. In the API (Enable OAuth Settings) area of the page, select *Enable OAuth Settings*.

8. Select the following OAuth scopes to apply to the connected app:
- Access and manage your data (API). 
- Perform requests on your behalf at any time (refresh_token, offline_access).
- (Optional) In case of data collection, if any permission issues arise, add the Full access (full) scope.

9. Select *Require Secret for the Web Server Flow* to require the app's client secret in exchange for an access token.

10. Select *Require Secret for Refresh Token Flow* to require the app's client secret in the authorization request of a refresh token and hybrid refresh token flow.

11. Click Save. It can take about 10 minutes for the changes to take effect.

12. Take Consumer Key and Secret from the Connected App API section.

## Logs reference

### Logout Rest

This is the `logout_rest` data stream. It represents events containing details about your organization's user logout history.

{{event "logout_rest"}}

{{fields "logout_rest"}}