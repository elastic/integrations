# Threat Map

The **Threat Map** dashboard visualizes network traffic flow between regions using directed paths and animations. It includes arrows indicating direction and pulsing arcs at the destination.

> **Note:** The animations may increase browser CPU usage.

---

## Prerequisites

To use the Threat Map dashboard, ensure the following:

- **Timestamp Field:** Documents must contain a `@timestamp` field for time-range filtering.
- **GeoIP Processor:** Apply a [GeoIP](https://www.elastic.co/guide/en/elasticsearch/reference/current/geoip-processor.html) processor to the IP field. The resulting document should contain `source.geo` and `destination.geo` fields.
  - Here is an example of an ingest pipeline that adds the geographical information to the `geo` field based on the `ip` field.

    ```
    PUT _ingest/pipeline/geoip
    {
      "description" : "Add ip geolocation info",
      "processors" : [
        {
          "geoip" : {
            "field" : "source.ip",
            "target_field" : "source.geo"
          }
        },
        {
          "geoip" : {
            "field" : "destination.ip",
            "target_field" : "destination.geo"
          }
        }
      ]
    }
    ```
- **Data View:** Use documents accessible via the `logs-*` data view.

---

## Data Format

Data is retrieved from Elasticsearch using the `_all` index search endpoint. Ensure the following fields exist in each document:

| Field                         | Description                                                        | Required/Optional | Default Value |
|-------------------------------|--------------------------------------------------------------------|-------------------|---------------|
| `source.geo.location.lat`     | Latitude of the source                                             | Required          |               |
| `source.geo.location.lon`     | Longitude of the source                                            | Required          |               |
| `source.geo.country_name`     | Country name of the source                                         | Required          |               |
| `source.ip`                   | IP address of the source                                           | Required          |               |
| `destination.geo.location.lat`| Latitude of the destination                                        | Required          |               |
| `destination.geo.location.lon`| Longitude of the destination                                       | Required          |               |
| `destination.geo.country_name`| Country name of the destination                                    | Required          |               |
| `destination.ip`              | IP address of the destination                                      | Required          |               |
| `color`                       | Arc color                                                          | Optional          | `"#54B399"`   |
| `animate`                     | Determines if the arc is animated                                  | Optional          | `false`       |
| `weight`                      | Arc line thickness                                                 | Optional          | `1`           |
| `source_label`                | Label at the source location                                       | Optional          |               |
| `destination_label`           | Label at the destination location                                  | Optional          |               |
| `pulse_at_source`             | If true, the pulse begins at the source instead of the destination | Optional          | `false`       |

> **Note:** These fields can be added or modified using `Custom pipeline`. [Read more](https://www.elastic.co/guide/en/fleet/current/data-streams-pipeline-tutorial.html).

---

## Usage

The Threat Map visualization can be added to other dashboards in two ways:

### 1. Duplicate the Dashboard
- Click the **Duplicate** button in the top-right corner of the dashboard.
- A clone of the dashboard will be created for your customization.

### 2. Copy Visualization to a Dashboard
- Click the three dots in the top-right corner of the visualization and select **Copy to Dashboard**.
- Choose one of the following options:
  - **Existing Dashboard:** Select an existing dashboard from the dropdown, then click **Copy and Go to Dashboard**.
  - **New Dashboard:** Create a new dashboard with the visualization.

![Copy to dashboard](../img/copy-to-dashboard.png?raw=true)
---

## Visualizations

The Threat Map dashboard includes the following visualizations:

### 1. Map
- **Framework:** Utilizes [Vega](https://vega.github.io/vega/) within Kibana.
- **Fields Used:** `source.geo.location`, `destination.geo.location`, `color`, `animate`, `weight`, `source_label`, and `destination_label`.
- **Customization:**
  - Click the three dots in the top-right corner and select **Maximize** to enlarge.
  - The map adapts to Kibana's dark/light mode automatically. [Read more](https://www.elastic.co/blog/whats-new-kibana-ml-8-8-0).

### 2. Panels
Includes four tables for analyzing traffic flow:
- **Source/Destination Countries:** Shows the top 5 countries with the highest traffic flow.
- **Source/Destination IPs:** Shows the top 5 IPs with the highest traffic flow.

Data in panels can be sorted by clicking on the **Count** column header.

---

## Filtering Data

### Global Filters
- Use **KQL (Kibana Query Language)** in the query bar at the top of the dashboard.
- Adjust the time range using the selector in the top-right corner (default: last 30 minutes).
- Maximum records displayed: **10,000**.

### Visualization-Specific Filters
- Click the three dots in the top-right corner of the map and select **Edit Visualization**.
- Apply a filter using the query bar.
- Click **Save and Return** to apply changes.

![Visualization-Specific Filters](../img/query-bar.png?raw=true)
---

## Customization Options

The following options are available for customization:

| Option              | Description                                               | Default Value         |
|---------------------|-----------------------------------------------------------|-----------------------|
| `emsTileServiceId`  | Sets the EMS-layer for the map.                           | `"undefined"`         |
| `Latitude`          | Starting latitude of the map                              |  `10`                 |
| `Longitude`         | Starting longitude of the map                             |  `0`                  |
| `Zoom`              | Starting zoom level of the map                            |  `1.3`                |
| `scrollWheelZoom`   | If true, disables mouse wheel zoom to avoid accidental zooming | `falses`         |

To customize these options, click on **Edit visualization** from the dropdown in the top right corner of the visualization. A Vega editor will open, where you can modify the following configurations.

For additional customization options, see the [Vega Kibana Guide](https://www.elastic.co/guide/en/kibana/current/vega.html#vega-with-a-map).

![Customization options](../img/customization-options.png?raw=true)
---
