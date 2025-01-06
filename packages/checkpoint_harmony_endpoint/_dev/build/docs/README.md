# Check Point Harmony Endpoint

The Check Point Harmony Endpoint integration allows you to ingest data from Harmony Endpoint management service(https://www.checkpoint.com/harmony/endpoint/).

Harmony Endpoint EPMaaS (Endpoint Management as a Service) is the cloud service to manage policies and deployments for Endpoint Security. It provides advanced threat prevention and detection capabilities to safeguard endpoints from malware, ransomware, and other sophisticated attacks. The solution offers real-time protection through behavioral analysis, machine learning, and threat intelligence.

For details please refer to the [Harmony Endpoint Admin guide](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Harmony-Endpoint-Admin-Guide/Topics-HEP/Introduction.htm)

## Setup

### To collect data from Check Point Harmony Endpoint, the following parameters from your Harmony Endpoint instance are required:

1. Server URL
2. Client ID
3. Secret key

To use this integration generate an API Key. API key consists of Client ID and Secret Key. Users can create API Keys by browsing to Infinity Portal at GLOBAL SETTINGS > API Keys. When creating an API Key, make sure that Service is set to Logs as a Service.

To create an API key please refer to Check Point's [Infinity API Guide](https://app.swaggerhub.com/apis-docs/Check-Point/infinity-events-api/1.0.0#/Authentication/getAuthToken). A list of servers can also be found there.

### Following are optional parameters which are used for fine-tuning:

1. Initial Interval: Initial interval for which existing logs will be pulled.
2. Interval: Interval at which new logs will be pulled.
3. Limit: Sets the number of results to return per API search query.
4. Page Limit: Sets the number of results to return per page, in API search query.

### Enabling Integration in Elastic

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Check Point Harmony Endpoint
3. Click on the "Check Point Harmony Endpoint" integration from the search results.
4. Click on the "Add Check Point Harmony Endpoint" button to add the integration.
5. Add all the required integration configuration parameters, such as Server URL, Client ID, Secret Key. For all data streams, these parameters must be provided in order to retrieve logs.
6. Save the integration.

## Data Streams:

1. **Anti-bot:** This is behavioral protection against bots. A single bot can create multiple threats. Cybercriminals often use bots in Advanced Persistent Threat (APT) attacks to target specific individuals or organizations.
2. **Anti-Malware:** Protects computers from viruses, spyware, and other malicious software. It uses real-time and scheduled scans to detect and neutralize threats before they can harm your computer.
3. **Forensics:** This component monitors file operations, processes, and network activity for suspicious behavior. It analyzes attacks detected by other client components or the Check Point Security Gateway and applies remediation to malicious files.
4. **Threat Emulation:** Detects zero-day and unknown attacks. Files on the endpoint computer are sent to a sandbox for emulation to uncover evasive zero-day attacks.
5. **Threat Extraction:** Proactively protects users from downloaded malicious files. It quickly delivers safe files while inspecting the originals for potential threats.
6. **URL Filtering:** Defines which websites are accessible within your organization. The URL Filtering policy consists of selected sites and the mode of operation applied to them.
7. **Zero-phishing:** Examines various website characteristics to ensure a site isn't impersonating another to maliciously collect personal information. It generates alerts for potential phishing sites.

## Logs Reference

### Anti-bot

This is `Anti-bot` dataset.

{{event "antibot"}}

{{fields "antibot"}}
A range of ECS fields are also exported. They are described in the [ECS documentation](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html).

### Anti-Malware

This is `Anti-Malware` dataset.

{{event "antimalware"}}

{{fields "antimalware"}}
A range of ECS fields are also exported. They are described in the [ECS documentation](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html).

### Forensics
This is `Forensics` dataset.

{{event "forensics"}}

{{fields "forensics"}}
A range of ECS fields are also exported. They are described in the ECS documentation.(https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

### Threat Emulation
This is `Threat Emulation` dataset.

{{event "threatemulation"}}

{{fields "threatemulation"}}
A range of ECS fields are also exported. They are described in the ECS documentation.(https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

### Threat Extraction
This is `Threat Extraction` dataset.

{{event "threatextraction"}}

{{fields "threatextraction"}}
A range of ECS fields are also exported. They are described in the ECS documentation.(https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

### URL Filtering
This is `URL Filtering` dataset.

{{event "urlfiltering"}}

{{fields "urlfiltering"}}
A range of ECS fields are also exported. They are described in the ECS documentation.(https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

### Zero-phishing
This is `Zero-Phishing` dataset.

{{event "zerophishing"}}

{{fields "zerophishing"}}
A range of ECS fields are also exported. They are described in the ECS documentation.(https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
