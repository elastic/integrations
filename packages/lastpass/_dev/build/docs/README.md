# LastPass

## Overview

The [LastPass](https://www.lastpass.com/) integration allows users to monitor Detailed Shared Folder Data, User Data, and Event Report Logs. LastPass is a cloud-based password manager that stores users' login information online in a secure database and allows users to generate unique passwords for each site they visit. In addition, LastPass stores all users' passwords and enables them to log into their accounts with ease. It’s available on all major platforms, including mobile devices, computers, and browser extensions.

## Data streams

The LastPass integration collects logs for three types of events: Detailed Shared Folder Data, User Data, and Event Report.

**Detailed Shared Folder Data** is used to get a detailed list of all shared folders, the sites within them, and the permissions granted to them. See more details in the doc [here](https://support.lastpass.com/help/get-detailed-shared-folder-data-via-lastpass-api).

**User Data** is used to get account details about the user. See more details in the doc [here](https://support.lastpass.com/help/get-user-data-via-lastpass-api).

**Event Report** is used to gather information about events that have taken place in the user's LastPass Business account. See more details in the doc [here](https://support.lastpass.com/help/event-reporting-via-lastpass-api).

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

  - **NOTE**
    - A **business account** is required to use the LastPass integration.
    - The LastPass **Provisioning API** does not support **managing groups for pre-configured SSO (Cloud) apps** for LastPass Business accounts.

## Setup

### To collect data from the LastPass REST APIs, follow the below steps:

1. Log in with the user's **email address** and **master password** to access the [Admin Console](https://admin.lastpass.com).
2. If prompted, complete the steps for **multifactor authentication** (if it is enabled for the user account).
3. To get an **Account Number(CID)**, follow the below steps:
  - On the **Dashboard** tab, the **Account Number(CID)** is located at the top of the page. it is preceded by the words **Account number**.
  ![LastPass Account Number](../img/lastpass-account-number-screenshot.png)
4. To create a **Provisioning Hash**, follow the below steps:
  - Go to **Advanced** -> **Enterprise API**.
  - Choose from the following options:
    - If the user has not previously created a provisioning hash, click **Create provisioning hash** -> **OK**, then the provisioning hash is shown at the top of the page.
    - If the user previously created a provisioning hash but has since forgotten it, the user can generate a new one.
    - **NOTE**: If the user has already created a provisioning hash, then generating a new one will invalidate the previous hash, and will require updating all integrations with the newly generated hash.
    - To proceed with creating a new provisioning hash, click **Reset your provisioning hash** -> **OK**, then a new provisioning hash is shown at the top of the page.
    ![LastPass Provisioning Hash](../img/lastpass-provisioning-hash-screenshot.png)

## Logs reference

### detailed_shared_folder

This is the `detailed_shared_folder` dataset.

#### Example

{{event "detailed_shared_folder"}}

{{fields "detailed_shared_folder"}}

### event_report

This is the `event_report` dataset.

#### Example

{{event "event_report"}}

{{fields "event_report"}}

### user

This is the `user` dataset.

#### Example

{{event "user"}}

{{fields "user"}}
