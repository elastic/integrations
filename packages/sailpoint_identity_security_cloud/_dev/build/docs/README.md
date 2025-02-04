# SailPoint Identity Security Cloud Integration

The Elastic integration for [SailPoint Identity Security Cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more.  
- This data stream leverages the SailPoint Identity Security Cloud API's `/v2024/search/events` endpoint to retrieve event logs.

## Requirements

### Generate a Personal Access Token (PAT)

Log in to the application with an administrator account and generate a **Personal Access Token (PAT)**. Personal access tokens are associated with a user in **SailPoint Identity Security Cloud** and inherit the user's permission level (e.g., Admin, Helpdesk, etc.) to determine access.

To create a **Personal Access Token (PAT)** using an **admin account**, follow the instructions provided in the official documentation:  
[Generate a Personal Access Token](https://developer.sailpoint.com/docs/api/v2024/authentication#generate-a-personal-access-token).

### Steps to Create a Personal Access Token

#### 1. Log in to SailPoint Identity Security Cloud
- Navigate to the **SailPoint Identity Security Cloud** portal.
- Sign in with your administrator credentials.

#### 2. Access API Authentication Settings
- Click on your **profile icon** (top-right corner).
- Select **Preferences** from the dropdown menu.

#### 3. Generate a New Personal Access Token
- Click on **Personal Access Tokens** and then click on **New Token**.
- Provide a **name/description** for the token to identify its purpose.

#### 4. Assign Permissions
- Select the necessary **API scopes and permissions** based on the required access level.
- Ensure you only grant the minimum permissions needed for security best practices.

#### 5. Generate & Copy the Token
- Click **Create** to create the PAT.
- Copy the generated token **immediately**, as it will not be shown again.
- Store it securely in a password manager or a secure vault.

## Logs

### Events

Event documents can be found by setting the following filter: 
`event.dataset : "sailpoint_identity_security_cloud.events"`

{{event "events"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}

