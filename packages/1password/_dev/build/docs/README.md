1Password
=========

With [1Password Business](https://support.1password.com/explore/business/), you can send your account activity to your security information and event management (SIEM) system using the 1Password Events API. Get reports about 1Password activity like sign-in attempts and item usage while you manage all your company’s applications and services from a central location.

With 1Password and Elastic SIEM, you can:

-	Control your 1Password data retention
-	Build custom graphs and dashboards
-	Set up custom alerts that trigger specific actions
-	Cross-reference 1Password events with the data from other services

You can set up Events Reporting if you’re an owner or administrator.  
Learn how to [obtain your 1Password Events API credentials](https://support.1password.com/events-reporting/#step-1-set-up-an-events-reporting-integration).

Events
------

### Sign-in Attempts

Uses the 1Password Events API to retrieve information about sign-in attempts. Events include the name and IP address of the user who attempted to sign in to the account, when the attempt was made, and – for failed attempts – the cause of the failure.

*Exported fields*

{{fields "signin_attempts"}}

{{event "signin_attempts"}}

### Item Usages

Uses the 1Password Events API to retrieve information about items in shared vaults that have been modified, accessed, or used. Events include the name and IP address of the user who accessed the item, when it was accessed, and the vault where the item is stored.

*Exported fields*

{{fields "item_usages"}}

{{event "item_usages"}}
