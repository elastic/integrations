---
name: Integration / Dataset creation or update
about: "Issue to track the creation or update of a new package or dataset."
labels: package

---

# Package / Dataset creation or update checklist

This checklist is intended for Devs which create or update a package to make sure they are consistent.

## All Changes

* [ ] Change follows [development guidelines](https://github.com/elastic/integrations/tree/master/doc/development/guidelines)
* [ ] Supported versions of the subject being monitored are documented
* [ ] Supported operating systems are documented (if applicable)
* [ ] [System tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/system_testing.md) exist
* [ ] Documentation
* [ ] Fields follow [ECS](https://github.com/elastic/ecs) and [naming conventions](https://www.elastic.co/guide/en/beats/devguide/master/event-conventions.html)
* [ ] Dashboards exists (if applicable)
* [ ] Screenshots of added / updated dashboards

## Log datasets

* [ ] [Pipeline tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/pipeline_testing.md) exist (if applicable)
* [ ] Test log files exist for the grok patterns
* [ ] Generated output for at least 1 log file exists

## Metric datasets

* [ ] Sample event (`sample_event.json`) exists

## New Packages

* [ ] Screenshot of the Fleet "Add Integration" Page.
