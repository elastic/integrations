# 1Password Events Reporting

With [1Password Business](https://support.1password.com/explore/business/), you can send your account activity to your security information and event management (SIEM) system, using the 1Password Events API. 

Get reports about 1Password activity, such as sign-in attempts and item usage, while you manage all your company’s applications and services from a central location.

With 1Password Events Reporting and Elastic SIEM, you can:

-	Control your 1Password data retention
-	Build custom graphs and dashboards
-	Set up custom alerts that trigger specific actions
-	Cross-reference 1Password events with the data from other services

You can set up Events Reporting if you’re an owner or administrator.  
Ready to get started? [Learn how to set up the Elastic Events Reporting integration](https://support.1password.com/events-reporting).

Events
------

### Sign-in Attempts

Use the 1Password Events API to retrieve information about sign-in attempts. Events include the name and IP address of the user who attempted to sign in to the account, when the attempt was made, and – for failed attempts – the cause of the failure.

*Exported fields*

{{fields "signin_attempts"}}

{{event "signin_attempts"}}

### Item Usages

This uses the 1Password Events API to retrieve information about items in shared vaults that have been modified, accessed, or used. Events include the name and IP address of the user who accessed the item, when it was accessed, and the vault where the item is stored.

*Exported fields*

{{fields "item_usages"}}

{{event "item_usages"}}
