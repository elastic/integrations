---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/define-deployment-modes.html
---

# Define deployment modes [define-deployment-modes]

Some integrations can be deployed on fully managed agents. These integrations are known as "agentless" integrations. Define the deployment mode of an integration with the [`deployment_modes`](#deployment_modes) property and display/hide variables in different deployment modes with the [`hide_in_deployment_modes`](#hide_in_deployment_modes) property.


## `deployment_modes` [deployment_modes]

Policy templates can indicate which deployment modes they support. Use the `deployment_modes` property in the policy template schema to define the supported deployment modes. Options are `default` and `agentless`. A policy template can support both modes.

Example policy template declaration:

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



## `hide_in_deployment_modes` [hide_in_deployment_modes]

Variables can be hidden in certain deployment modes. Use the `hide_in_deployment_modes` property to opt variables in or out of being displayed in default or agentless mode. This property works at any manifest level.

Example variable declaration:

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

1. Disables visibility of the variable in agent deployment mode
2. Disables visibility of the variable in agentless deployment mode


For more information on variable property definitions, refer to [Define variable properties](/extend/finishing-touches.md#define-variable-properties).


## Agentless capabilities [agentless-capabilities]

The capabilities feature protects agentless deployments from allowing undesired inputs to run. A static `capabilities.yml` file defines these allowed and disallowed inputs and is passed to deployed agents. To determine which capabilities are currently allowed on Agentless, refer to [`capabilities.yml`](https://github.com/elastic/agentless-controller/blob/main/controllers/config/capabilities.yml).
