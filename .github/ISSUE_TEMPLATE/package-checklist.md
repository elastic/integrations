---
name: Integration / Dataset creation or update
about: "Issue to track the creation or update of a new package or dataset."
labels: integration

---

# Package / Dataset creation or update checklist

This checklist is intended for Devs which create or update a package to make sure they are consistent.

<!--

If the change targets a specific ES / Kibana / Agent version, uncomment this line and specify version.

* [ ] Required Kibana version set to target version: 

-->

## All Changes

* [ ] Change follows [development guidelines](https://github.com/elastic/integrations/tree/master/doc/development/guidelines)
* [ ] Supported versions of the subject being monitored are documented
* [ ] Supported operating systems are documented (if applicable)
* [ ] [System tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/system_testing.md) exist
* [ ] Documentation
* [ ] Fields follow [ECS](https://github.com/elastic/ecs) and [naming conventions](https://www.elastic.co/guide/en/beats/devguide/master/event-conventions.html)
* [ ] Dashboards exists (if applicable)
* [ ] Screenshots of added / updated dashboards
* [ ] At least a manual test with ES / Kibana / Agent has been performed.
* [ ] The required Kibana version is set to the lowest version used in the manual test.

## Log datasets

* [ ] [Pipeline tests](https://github.com/elastic/elastic-package/blob/master/docs/howto/pipeline_testing.md) exist (if applicable)
* [ ] Test log files exist for the grok patterns
* [ ] Generated output for at least 1 log file exists

## Metric datasets

This entry is currently _recommended_. It will be mandatory once we provide better support for it.

* [ ] Sample event (`sample_event.json`) exists

## New Packages

* [ ] Screenshot of the Fleet "Add Integration" Page.
