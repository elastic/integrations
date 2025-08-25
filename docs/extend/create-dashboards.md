---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/create-dashboards.html
---

# Create and export dashboards [create-dashboards]

Visualizing integration data in a meaningful way is an important aspect of an integration.

When creating a new integration, it’s important to add dashboards.

To get started, create a new dashboard, or customize an existing one. You can use `elastic-package` to boot up the service stack. Navigate to the package you want to create dashboards for, and run:

```bash
elastic-package service
```

When you’re done making changes, you can use `elastic-package` to export the dashboards and their dependencies to the package source.


## Dashboard planning [_dashboard_planning]

Many integrations cover more than one component of a target system. For example, the RabbitMQ module provides several metricsets covering connection, exchange, node, queue. It makes sense to break this information down into several interconnected dashboards. The default one is an overview of a target system, and the others provide deep-dives into the various parts of the target system. The content of the Overview dashboard should be cherry-picked from all datasets and individually compiled for every such integration.


### Metrics [_metrics]

Always check the type of a metric and ensure that the correct transformation is applied where applicable. For example, in most cases for cumulative counters, it makes sense to use the rate function.


### Visualization type [_visualization_type]

For new visualizations, we recommend using Lens first. If what you’re trying to achieve cannot be accomplished with the current capabilities of Lens, try TSVB.


### Filters [_filters]

When building a dashboard, always consider adding a filter dropdown. Why? In most cases, the integrations monitor multiple instances of a target system, so we need to provide a way to switch between them.

To build a filter dropdown, use the Controls visualization. Here’s an example of a host name dropdown that you can add to the System dashboard:


### Navigation [_navigation]

If an integration has several dashboards, ensure that you can easily navigate all of them. To build dashboard navigation, use the Markdown visualization type.

For example, the System dashboard provides the following navigation:

Source:

```text
[System Overview](#/dashboard/system-Metrics-system-overview-ecs)  | [Host Overview](#/dashboard/system-79ffd6e0-faa0-11e6-947f-177f697178b8-ecs) |
[Containers overview](#/dashboard/system-CPU-slash-Memory-per-container-ecs)
```

While this can work, it doesn’t highlight the selected dashboard. Unfortunately the Markdown control is not optimized for navigation, which makes it cumbersome to build navigation with highlighted links because each link should be highlighted separately. This means that the navigation control you’re building has to be cloned as many times as there are dashboard to ensure proper link highlighting. E.g.

```text
**[System Overview](#/dashboard/system-Metrics-system-overview-ecs)**  | [Host Overview](#/dashboard/system-79ffd6e0-faa0-11e6-947f-177f697178b8-ecs) |
[Containers overview](#/dashboard/system-CPU-slash-Memory-per-container-ecs)

[System Overview](#/dashboard/system-Metrics-system-overview-ecs)  | **[Host Overview](#/dashboard/system-79ffd6e0-faa0-11e6-947f-177f697178b8-ecs)** |
[Containers overview](#/dashboard/system-CPU-slash-Memory-per-container-ecs)

[System Overview](#/dashboard/system-Metrics-system-overview-ecs)  | [Host Overview](#/dashboard/system-79ffd6e0-faa0-11e6-947f-177f697178b8-ecs) |
**[Containers overview](#/dashboard/system-CPU-slash-Memory-per-container-ecs)**
```


### Target system name [_target_system_name]

Currently we don’t make it a rule to show on a dashboard what system it’s designed to monitor. The only way to see it is through the dashboard name.

When using multiple dashboards on bigger screens, it makes it hard to distinguish between the dashboards. You can improve this by using the Markdown control to display the target system the dashboard is used for.


### Naming [_naming]

When building dashboards, use the following naming convention.


#### Visualizations [_visualizations]

```text
<Name>
```

Examples:

* Memory Usage Gauge
* New groups

To avoid adding repetitive information such as the package name, rename all visualizations added to a dashboard only to show the <Name> part.


#### Dashboards [_dashboards]

```text
[<Metrics | Logs> <PACKAGE NAME>] <Name>
```

Examples:

* [Metrics System] Host overview
* [Metrics MongoDB] Overview


### Screenshots [_screenshots]

Letter casing is important for screenshot descriptions. Descriptions are shown in the {{kib}} UI, so try and keep them clean and consistent.

These descriptions are visualized in the {{kib}} UI. It would be better experience to have them clean and consistent.

* Bad candidate: filebeat running on ec2 machine
* Good candidates: {{filebeat}} running on AWS EC2 machine


## Exporting [_exporting]

```bash
elastic-package export
```

