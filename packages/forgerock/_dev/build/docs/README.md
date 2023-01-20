# ForgeRock Identity Platform

ForgeRock is a modern identity platform which helps organizations radically simplify identity and access management (IAM) and identity governance and administration (IGA). The ForgeRock integration collects audit logs from the [API](https://backstage.forgerock.com/knowledge/kb/article/a37739488).

### Configuration

Authorization parameters for the ForgeRock Identity Cloud API (`API Key ID`, and `API Key Secret`) can be created [in the Identity Cloud admin UI](https://backstage.forgerock.com/docs/idcloud/latest/developer-docs/authenticate-to-rest-api-with-api-key-and-secret.html#get_an_api_key_and_secret). 

## Logs

### AM_Access events

This is the `forgerock.am_access` dataset. These logs capture all incoming Identity Cloud access calls as audit events. This includes who, what, when, and the output for every access request. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#am-access).

{{event "am_access"}}

{{fields "am_access"}}

### AM_Activity events

This is the `forgerock.am_activity` dataset. These logs capture state changes to objects that have been created, updated, or deleted by Identity Cloud end users. This includes session, user profile, and device profile changes. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#am-activity).

{{event "am_activity"}}

{{fields "am_activity"}}

### AM_Authentication events

This is the `forgerock.am_authentication` dataset. These logs capture when and how a user is authenticated and related audit events. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#am-authentication).

{{event "am_authentication"}}

{{fields "am_authentication"}}

### AM_Config events

This is the `forgerock.am_config` dataset. These logs capture access management configuration changes for Identity Cloud with a timestamp and by whom. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#am-config).

{{event "am_config"}}

{{fields "am_config"}}

### AM_Core events

This is the `forgerock.am_core` dataset. These logs capture access management debug logs for Identity Cloud. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#am-core).

{{event "am_core"}}

{{fields "am_core"}}

### IDM_access events

This is the `forgerock.idm_access` dataset. These logs capture messages for the identity management REST endpoints and the invocation of scheduled tasks. This is the who, what, and output for every identity management access request in Identity Cloud. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#idm-access).

{{event "idm_access"}}

{{fields "idm_access"}}

### IDM_activity events

This is the `forgerock.idm_activity` dataset. These logs capture operations on internal (managed) and external (system) objects in Identity Cloud. idm-activity logs the changes to identity content, such as adding or updating users, changing passwords, etc. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#idm-activity).

{{event "idm_activity"}}

{{fields "idm_activity"}}

### IDM_authentication events

This is the `forgerock.idm_authentication` dataset. These logs capture the results when you authenticate to an /openidm​ endpoint to complete certain actions on an object. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#idm-authentication).

{{event "idm_authentication"}}

{{fields "idm_authentication"}}

### IDM_config events

This is the `forgerock.idm_config` dataset. These logs capture configuration changes to Identity Cloud with a timestamp and by whom. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#idm-config).

{{event "idm_config"}}

{{fields "idm_config"}}

### IDM_core events

This is the `forgerock.idm_core` dataset. These logs capture identity management debug logs for Identity Cloud. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#idm-core).

{{event "idm_core"}}

{{fields "idm_core"}}

### IDM_sync events

This is the `forgerock.idm_sync` dataset. These logs capture any changes made to an object resulting in automatic sync (live sync and implicit sync) to occur when you have a repository mapped to Identity Cloud. More information about [these logs](https://backstage.forgerock.com/knowledge/kb/article/a37739488#idm-sync).

{{event "idm_sync"}}

{{fields "idm_sync"}}