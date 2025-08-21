---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/policy-testing.html
---

# Policy testing [policy-testing]

Policy tests allow you to verify that an integration policy will be accepted by Fleet, and will create an expect Elastic Agent policy.

An Elastic Agent policy is used by Fleet to define the data that will be collected by the Elastic Agent. Within the Elastic Agent policies is a set of integration policies, which define how each integration's input will be configured.

Policy tests allow you to define the expected integration policy, and test that the generated policy is correct.

For more details, see [HOWTO: Writing policy tests for a package](https://github.com/elastic/elastic-package/blob/main/docs/howto/policy_testing.md)

## Running policy tests [policy-tests]

Policy tests don’t require the {{stack}} to be up and running. Simply navigate to the package’s root folder (or any sub-folder under it) and run the following command.

```bash
elastic-package test policy
```
