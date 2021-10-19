1Password Events Reporting
==========================

With [1Password Business](https://support.1password.com/explore/business/), you can send your account activity to your security information and event management (SIEM) system using the 1Password Events API. Get reports about 1Password activity like sign-in attempts and item usage while you manage all your company’s applications and services from a central location.

With 1Password Events Reporting and Elastic SIEM, you can:

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

| Field                                 | Description                                                                                                                                               |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `@timestamp`                          | The date and time of the sign-in attempt                                                                                                                  |
| `event.action`                        | The category of the sign-in attempt                                                                                                                       |
| `user.id`                             | The UUID of the user that attempted to sign in to the account                                                                                             |
| `user.full_name`                      | The name of the user, hydrated at the time the event was generated                                                                                        |
| `user.email`                          | The email address of the user, hydrated at the time the event was generated                                                                               |
| `os.name`                             | The name of the operating system of the user that attempted to sign in to the account                                                                     |
| `os.version`                          | The version of the operating system of the user that attempted to sign in to the account                                                                  |
| `source.ip`                           | The IP address that attempted to sign in to the account                                                                                                   |
| `onepassword.uuid`                    | The UUID of the event                                                                                                                                     |
| `onepassword.session_uuid`            | The UUID of the session that created the event                                                                                                            |
| `onepassword.type`                    | Details about the sign-in attempt                                                                                                                         |
| `onepassword.country`                 | The country code of the event. Uses the ISO 3166 standard                                                                                                 |
| `onepassword.details`                 | Additional information about the sign-in attempt, such as any firewall rules that prevent a user from signing in                                          |
| `onepassword.client.app_name`         | The name of the 1Password app that attempted to sign in to the account                                                                                    |
| `onepassword.client.app_version`      | The version number of the 1Password app                                                                                                                   |
| `onepassword.client.platform_name`    | The name of the platform running the 1Password app                                                                                                        |
| `onepassword.client.platform_version` | The version of the browser or computer where the 1Password app is installed, or the CPU of the machine where the 1Password command-line tool is installed |

### Item Usages

Uses the 1Password Events API to retrieve information about items in shared vaults that have been modified, accessed, or used. Events include the name and IP address of the user who accessed the item, when it was accessed, and the vault where the item is stored.

*Exported fields*

| Field                                 | Description                                                                                                                                               |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `@timestamp`                          | The date and time of the sign-in attempt                                                                                                                  |
| `user.id`                             | The UUID of the user that accessed the item                                                                                                               |
| `user.full_name`                      | The name of the user, hydrated at the time the event was generated                                                                                        |
| `user.email`                          | The email address of the user, hydrated at the time the event was generated                                                                               |
| `os.name`                             | The name of the operating system the item was accessed from                                                                                               |
| `os.version`                          | The version of the operating system the item was accessed from                                                                                            |
| `source.ip`                           | The IP address the item was accessed from                                                                                                                 |
| `onepassword.uuid`                    | The UUID of the event                                                                                                                                     |
| `onepassword.used_version`            | The version of the item that was accessed                                                                                                                 |
| `onepassword.vault_uuid`              | The UUID of the vault the item is in                                                                                                                      |
| `onepassword.item_uuid`               | The UUID of the item that was accessed                                                                                                                    |
| `onepassword.client.app_name`         | The name of the 1Password app the item was accessed from                                                                                                  |
| `onepassword.client.app_version`      | The version number of the 1Password app                                                                                                                   |
| `onepassword.client.platform_name`    | The name of the platform the item was accessed from                                                                                                       |
| `onepassword.client.platform_version` | The version of the browser or computer where the 1Password app is installed, or the CPU of the machine where the 1Password command-line tool is installed |
