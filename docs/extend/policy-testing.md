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

Policy tests require the {{stack}} to be running. Start the Elastic stack with elastic-package, if it's not already running. Then simply navigate to the package’s root folder (or any sub-folder under it) and run the following command.

```bash
# Start the stack (if not already running)
elastic-package stack up -d

# Run policy tests
elastic-package test policy
```
