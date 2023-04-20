# Collective Intelligence Framework v3 Integration

This integration connects with the [REST API from the running CIFv3 instance](https://github.com/csirtgadgets/bearded-avenger-deploymentkit/wiki/REST-API) to retrieve indicators.

## Data Streams

### Feed

The CIFv3 integration collects threat indicators based on user-defined configuration including a polling interval, how far back in time it should look, and other filters like indicator type and tags.

CIFv3 `confidence` field values (0..10) are converted to ECS confidence (None, Low, Medium, High) in the following way:

| CIFv3 Confidence | ECS Conversion |
| ---------------- | -------------- |
| Beyond Range     | None           |
| 0 - \<3          | Low            |
| 3 - \<7          | Medium         |
| 7 - 10           | High           |

{{fields "feed"}}

{{event "feed"}}
