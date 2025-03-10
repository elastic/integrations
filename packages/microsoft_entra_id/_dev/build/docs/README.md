# Microsoft Entra ID Integration  

This integration is for [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id). It supports directory audit, sign-in, and provisioning data streams from Microsoft Entra ID activity logs.  

## Prerequisites  
Before setting up this integration, ensure the following:  
- You have **Microsoft Entra ID P1 or P2** licensing (required for sign-in logs).  
- You have access to **Microsoft Entra ID Admin Center**.  
- You have **Global Admin** or **Security Admin** privileges to grant API permissions.  

## Setup  

To use this integration, you must:  
1. **Enable Audit Logs** in your Microsoft Entra ID tenant.  
2. **Register an application** in [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate%2Cexpose-a-web-api).  

### Register an Application  
1. In the Microsoft Entra ID portal, navigate to **App registrations** and register a new application.  
2. **Note the following details** from the **Overview** page:  
   - `Application (client) ID`  
   - `Directory (tenant) ID`  

### Configure Authentication  
1. Navigate to **Certificates & Secrets** → **New client secret**.  
2. Provide a description and create a new secret.  
3. **Copy and save the `Value`** of the secret. This is required for authentication.  

### Assign API Permissions
1. Navigate to **API permissions** → **Add a permission** → **Microsoft Graph**.  
2. Select **Application permissions** and add the following:  
   - **Sign-in Logs** → `AuditLog.Read.All`  
   - **Provisioning Logs** → `AuditLog.Read.All`  
   - **Directory Audit Logs** → `AuditLog.Read.All`  
   - (Optional) `Directory.Read.All` (for additional user directory data)  
3. Click **Add permissions** and **Grant admin consent**. 

### Integrate with Elastic Agent  
Once the secret is created and permissions are granted:  
1. Click **Add Microsoft Entra ID (CEL)** in Elastic Agent.  
2. Enable **Collect Microsoft Entra ID logs from Microsoft Graph APIs (v1) via Elastic Agent**.  
3. Provide the following details:  
   - **Directory (tenant) ID** (from the Overview page)  
   - **Application (client) ID**  
   - **Client Secret Value**  
   - **OAuth2 Token URL** (optional; defaults to the provided tenant ID)  
4. Modify additional parameters as needed.  

This setup enables secure access to Microsoft Entra ID logs via the Microsoft Graph API.

## Logs

### Directory Audit Logs

Uses the Microsoft Graph APIs (v1) to fetch directory audit logs

{{event "directory_audit"}}

{{fields "directory_audit"}}