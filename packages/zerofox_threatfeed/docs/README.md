# ZeroFOX Threatfeed Integration

The ZeroFOX Threatfeed integration collects and parses indicator data from the the ZeroFOX Threatfeed API.

## Compatibility

This integration supports the ZeroFOX Threatfeed API v1.0

### ZeroFOX

Contains alert data received from the ZeroFOX Threatfeed API

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| threatfeed.id | Unique identifier of this indicator. | keyword |
| threatfeed.indicator_type | Type of indicator. | keyword | 
| threatfeed.value | Original source url of the discovered content. | keyword |
| threatfeed.network | Network where the content was found. | keyword |
| threatfeed.classifications.id | Unique identifier of the classification. | keyword |
| threatfeed.classifications.name | Name of the classification. | keyword |
| threatfeed.classifications.privacy_level | Privacy Level for the classification. | keyword |
| threatfeed.classifications.created_at | Time when the classification was created. | date | 
| threatfeed.classifications.updated_at | Time when the classification was last updated. | date |
| threatfeed.campaigns | campaigns | keyword |
| threatfeed.privacy_level | Privacy Level for the indicator. | keyword |
| threatfeed.created_at Time when the indicator was created. | date |
| threatfeed.updated_at | Time when the indicator was last updated. | date |
| threatfeed.threat_level | Threat level of the indicator. | keyword | 
| threatfeed.expired | indicator status. | keyword |
| threatfeed.ttl | ttl of the indicator. | date |
