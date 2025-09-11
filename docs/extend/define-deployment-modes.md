---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/define-deployment-modes.html
---

# Define deployment modes [define-deployment-modes]


## What are deployment modes [what-are-deployment-modes]

Deployment modes let you choose how an integration is installed and managed.

* Default mode: Your install and manage {{agent}} yourself (for example using {{fleet}}).
* Agentless mode: {{stack}} manages the agents for you, no need to install anything yourself.

Some integrations can support both modes, while others may only support one.


## How to set deployment modes [set-deployment-modes]

When you create a policy template for your integration, you can specify which modes it supports using the `deployment_modes` property.

Example:

```yaml
format_version: 3.2.0
name: aws
title: AWS
version: 2.13.1
...
policy_templates:
  - name: billing
    title: AWS Billing
    description: Collect billing metrics with Elastic Agent
    deployment_modes: <1>
      default:
        enabled: false <2>
      agentless:
        enabled: true <3>
    data_streams:
      - billing
    ...
```

1. Defines the supported deployment modes
2. Disables agent deployment support
3. Enables agentless deployment support

Here, only agentless mode is enable for the "billing" template.


## Hiding variables based on deployment mode [hide-in-deployment-modes]

Sometimes, you want certain configuration options to show up only in specific modes. Use the `hide_in_deployment_modes` property for this.

Example:

```yaml
streams:
  - input: filestream
    vars:
      - name: paths
        type: text
        title: Paths
        multi: true
        required: true
        show_user: true
        default:
          - /var/log/my-package/*.log
      - name: agentless_only
        type: text
        title: Agentless only variable
        multi: false
        required: false
        show_user: true
        hide_in_deployment_modes: <1>
          - default
     - name: hidden_in_agentless
       type: text
       title: Hidden in agentless variable
       multi: false
       required: false
       show_user: true
       hide_in_deployment_modes: <2>
         - agentless
```

1. Disables visibility of the variable in default deployment mode
2. Disables visibility of the variable in agentless deployment mode

This helps keep the UI clean and relevant for each deployment type.
For more information on variable property definitions, refer to [Define variable properties](/extend/finishing-touches.md#define-variable-properties).

## Agentless capabilities [agentless-capabilities]

Agentless deployments are protected by a capabilities file (capabilities.yml). This file lists what inputs and features are allowed or blocked in agentless mode, making sure only safe and supported features run.

You can see the current allowed capabilities in the [`capabilities.yml`](https://github.com/elastic/agentless-controller/blob/main/controllers/config/capabilities.yml).
