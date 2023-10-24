---
name: Integration release checklist
about: "Track the release process for a new feature or a new integration"
labels: release-pending
---

# Integration release checklist

This checklist is intended for integrations maintainers to ensure consistency
when creating or updating a Package, Module or Dataset for an Integration.

### All changes

- [ ] Change follows the [contributing guidelines](https://github.com/elastic/integrations/blob/main/CONTRIBUTING.md)
- [ ] Supported versions of the monitoring target are documented
- [ ] Supported operating systems are documented (if applicable)
- [ ] Integration or [System tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/system_testing.md) exist
- [ ] Documentation exists, [useful guidelines](https://github.com/elastic/integrations/blob/main/docs/documentation_guidelines.md) to follow
- [ ] Fields follow [ECS](https://github.com/elastic/ecs) and [naming conventions](https://www.elastic.co/guide/en/beats/devguide/master/event-conventions.html)
- [ ] At least a manual test with ES / Kibana / Agent has been performed.
- [ ] Required Kibana version set to:

<!-- Uncomment as many of the following sections as needed
### New Package

- [ ] Screenshot of the "Add Integration" page on Fleet added

### Dashboards changes

- [ ] Dashboards exists
- [ ] Screenshots added or updated
- [ ] Datastream filters added to visualizations

### Log dataset changes

- [ ] [Pipeline tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/pipeline_testing.md) exist (if applicable)
- [ ] Generated output for at least 1 log file exists

### Metric dataset changes

_This entry is currently only recommended. It will be mandatory once we provide better support for it._

- [ ] Sample event (`sample_event.json`) exists

### Filebeat module changes

- [ ] Test log files exist for the grok patterns
- [ ] Generated output for at least 1 log file exists

### Metricbeat module changes

- [ ] Example `data.json` exists and an automated way to generate it exists (`go test -data`)
- [ ] Test environment in Docker exist for integration tests
-->
