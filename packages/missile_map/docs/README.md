## Missile Map

The Missile Map dashboard provides insights into the flow of network traffic between two regions. It displays animated paths from the source to the destination, with missile-like arrows along the path and a pulsing arc at the end.

> **Note:** Animated paths may result in increased browser CPU usage.
> 

## Pre-requisities

- Kibana version `8.10.0` or higher is required.
- The documents must contain a `@timestamp` field, which is required for filtering by time range.
- A [GeoIP](https://www.elastic.co/guide/en/elasticsearch/reference/current/geoip-processor.html) processor must be applied to the IP field, providing location data for both the source and destination. This data should be available in the `source.geo.location` and `destination.geo.location` fields.
- Documents should be accessible via the `logs-*` data view.

## Data

Data is retrieved from Elasticsearch using the `_all` index search endpoint.

The visualization looks for the following fields in a document:

  * source.geo.location.lat: Latitude of the source. (required)
  * source.geo.location.lon: Longitude of the source. (required)
  * source.geo.country_name: Country name of the source. (required)
  * source.ip: IP address of the source. (required)
  * destination.geo.location.lat: Latitude of the destination. (required)
  * destination.geo.location.lon: Longitude of the destination. (required)
  * destination.geo.country_name: Country name of the destination. (required)
  * destination.ip: IP address of the destination. (required)
  * color: Arc color (optional, default "steelblue")
  * animate: Determines if the arc is animated (optional, default "false")
  * weight: Arc line thickness. (optional, default 1)
  * source_label: Label at the arc’s start. If multiple arcs share the same start point, this label should be the same for consistency.
  * destination_label: Label at the arc’s end. If multiple arcs share the same end point, this label should be the same for consistency.

## Visualizations

There are two types of visualizations used in the Missile Map dashboard:

1. **Map**

    The map visualization uses the Elastic Map Service to add a basemap. For the marks (path, text, arc, etc.) and animations, it uses the [Vega](https://vega.github.io/vega/) visualization framework within Kibana.

    The map visualization is based on the following fields: `source.geo.location`, `destination.geo.location`, `color`, `animate`, `weight`, `source_label`, and `destination_label`.

    The document may include the following optional fields to configure each path on the map:
    - `color`: Accepts a color name or hash code.
    - `animate`: A boolean that can be set to configure a path as animating.
    - `weight`: Configures the width of a path.
    - `source_label` and `destination_label`: Text that is shown at the start and end of a path respectively.

    The map visualization can be expanded by clicking on the three dots on the top right corner and selecting `⤢ Maximize` from the dropdown.
    The map follows an auto-switch dark-light behavior, meaning it will sync with the Kibana UI theme. See more [here](https://www.elastic.co/blog/whats-new-kibana-ml-8-8-0).

2. **Panels**

    There are four tables to analyze the network traffic flow. These tables are based on the `source.ip`, `destination.ip`, `source.geo.country_name`, and `destination.geo.country_name` fields.


   - **Source/Destination Countries**

        These panels show the top 5 source/destination countries with the highest traffic flow.

   - **Source/Destination IP**

        These panels show the top 5 source/destination IP addresses with the highest traffic flow.

    Users can sort the data by clicking on the Count column header and selecting the sorting order.

## Filter data

Kibana allow users to filter data by writing KQL (Kibana Query Language) in the query bar on the top.
Users can filter data by selecting the time range provided in the right corner.

By default, the time window is set to the last 30 minutes. To display a path on the map, adjust the time range. A maximum of 10000 records can be displayed.
