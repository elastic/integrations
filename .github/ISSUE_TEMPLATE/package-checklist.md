---
name: New Module / Dataset
about: "Issue to track the creation or update of a new package or dataset."
labels: package

---

# Package / Dataset creation or update checklist

This checklist is intended for Devs which create or update a package to make sure they are consistent.

## All Changes

* [ ] Change follows [development guidelines](https://github.com/elastic/integrations/tree/master/doc/development/guidelines)
* [ ] Supported versions are documented
* [ ] Supported operating systems are documented (if applicable)
* [ ] [Pipeline tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/pipeline_testing.md) exist (if applicable)
* [ ] [System tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/system_testing.md) exist
* [ ] Automated checks that all fields are documented
* [ ] Documentation
* [ ] Fields follow [ECS](https://github.com/elastic/ecs) and [naming conventions](https://www.elastic.co/guide/en/beats/devguide/master/event-conventions.html)
* [ ] Dashboards exists (if applicable)

## Log datasets

* [ ] Test log files exist for the grok patterns
* [ ] Generated output for at least 1 log file exists

## Metric datasets

* [ ] Example `data.json` exists and an automated way to generate it exists (`go test -data`)
* [ ] Test environment in Docker exist for integration tests

## Additional Requirements for moving to GA

_TODO_
