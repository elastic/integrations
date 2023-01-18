# Dashboard guidelines

A [Kibana dashboard][1] is a set of one or more panels, also referred as visualizations. Panels display data in charts, tables, maps, and more. Dashboards support several types of panels to display your data, and several options to create panels.

The goal of each integration dashboard is to:

* Provide a way to explore ingested data out of the box.
* Provide an overview of the monitored resources through installing the integration.

Each integration package should contain one or more dashboards.

## Out of date fields in dashboards

The dashboards must be updated to reflect any changes to field names or types. If a PR updates a field name or type, make sure it is correctly updated in any dashboard the field is being used into.

## TSDB visualizations

Migrate the dashboards from TSVB to Lens where possible. If it's not possible, please engage with the Kibana team to identify any gaps that prevent from full TSVB to Lens dashboard migration.

## Visualizations by value, not by reference

Kibana visualizations can be added in a dashboard by value or by reference. Historically by value did not exist. Switching to value has the advantage that the dashboards are fully self contained and only need a single request to be installed.

To achieve this:
- Migrate existing dashboards from by reference to by value.
- Create new dashboards adding visualizations by value.

A migration script has been created to help with the migration: [flash1293/legacy_vis_analyzer][2]

## Visualizations should contain a filter

Kibana visualizations can define a filter to avoid performance issues querying all `metrics-*` or `logs-*` indices.

It is recommended to set a filter in each visualization at least by the required `data_stream.dataset`. More details about the Elastic data stream naming scheme [here][4].

Example of this filter: 
- [System visualization - User Logon Dashboard][3]


[1]: https://www.elastic.co/guide/en/kibana/current/dashboard.html
[2]: https://github.com/flash1293/legacy_vis_analyzer
[3]: https://github.com/elastic/integrations/blob/5176089e30cf2932d6e5ca7c90caa2ab9a237bee/packages/system/kibana/visualization/system-18348f30-a24d-11e9-a422-d144027429da.json#L9
[4]: https://www.elastic.co/blog/an-introduction-to-the-elastic-data-stream-naming-scheme
