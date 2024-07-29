                            
## JAMF PRO INTEGRATION

- JAMF Pro Integration empowers with the capability to supervise and monitor devices that are being controlled via the JAMF Pro dashboard.

- Utilize the JAMF Pro Integration to supervise and monitor devices that are being controlled via the JAMF Pro dashboard.

- Once the integration is done, it allows to visualize the data through Kibana, enabling to create alerts to proactively address any issues found.

## Data streams

 * __inventory__ provides Inventory data for computers. Includes: hardware, OS, etc. Saves each device as a separate log record.

 The inventory component is a critical part of JAMF Pro Integration. It focuses on providing comprehensive inventory data pertaining to computers. This includes -

Hardware: Get detailed information about the hardware aspects of your computer. This encompasses data about your CPU, memory, storage, network interfaces, and more.

Operating System: The inventory also includes in-depth information about the operating system installed on the computer, such as the current version, build number, updates, etc.

## Requirements

To properly utilize the features of the application and ensure smooth operation, there are certain prerequisites that need to be met:

- Elasticsearch and Kibana
It needs Elasticsearch for efficient storage and search processes for your data. Alongside Elasticsearch, Kibana is also necessary for visualizing and managing the data effectively.

We understand the varying needs of different organizations and thus provide two options:

Hosted Elasticsearch Service on Elastic Cloud: This is recommended option for convenience and optimized performance. This service packs powerful features of elastic search and Kibana without the need for hardware or installation procedures.

Self-managed Elastic Stack: If you prefer more control and responsibility over the data, it can be opted for managing the Elastic Stack on a hardware. This option provides more flexibility in terms of customization.

- JAMF Pro Active License and OAuth2 Credentials
For smooth integration, an active license for JAMF Pro is required. Additionally, OAuth2 credentials obtained via the API App are necessary. These credentials are essential to authenticate and establish a secure connection with the API.

- JAMF API Application Permissions
To ensure proper functionality and access to pertinent features, the API application must have the following permissions:

Read Computer Inventory Collection: Access to read inventory data from the computer collection.
Read Mobile Devices: Permission to access data related to mobile devices.
Read Computers: Allows the application to access and read data from computers.
Read Mobile Device Inventory Collection: Access to the mobile devices inventory collection.
It is crucial that all these prerequisites are met to facilitate a smoother integration process and optimized application experience.

## Setup

- Establishing A Connection to JAMF Pro:

Setting up a successful connection with JAMF Pro involves creating an application and configuring the integration.

## Step 1: Create an Application in JAMF Pro:

To create a connection to JAMF Pro, an [application must be created](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) first. Credentials generated during this process are required for the subsequent steps.

## Step 2: Integration Setup:

Once the application is created and credentials are obtained, proceed with setting up the integration. For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.This guide includes comprehensive step-by-step instructions for configuring Kibana to connect with JAMF Pro, to initializing data feeds. Follow each step meticulously for a successful and seamless integration.

## FEATURES DEVELOPED:

- The development team has implemented the following robust features in the application:

1. Jamf Pro connection with  OAuth2.
2. Data logging. Each device as single doc.
3. Fingerprint feature.

## REMAINING DEVELOPMENT:

- The following features are currently under development and will be incorporated into future updates of the application:

1. Testing.
2. UI Dashboard.
3. Section Configuration.
4. Fingerprint flexible approach.
