## Summary
This PR adds support for parsing 6 Security Group Tag (SGT) and Endpoint Group (EPG) fields from Cisco FTD connection event syslog messages (message IDs 430002 and 430003).

## Related Issue
Fixes #15204

## Problem
The Cisco FTD integration was not parsing SGT/EGT-related fields from connection event messages. These fields were present in the `event.original` field but were not being extracted into structured, queryable fields, making it difficult to search and analyze security group information in Elastic.

## Solution
Added parsing support for the following 6 fields:

| Field | Target Field | Type | Description |
|-------|---------------|------|-------------|
| `SourceSecurityGroup` | `cisco.ftd.security_event.source_security_group` | keyword | Security Group of the source |
| `SourceSecurityGroupTag` | `cisco.ftd.security_event.source_security_group_tag` | keyword | Numeric SGT attribute of source |
| `SourceSecurityGroupType` | `cisco.ftd.security_event.source_security_group_type` | keyword | Source SGT type (Inline, Session Directory, SXP) |
| `DestinationIP_DynamicAttribute` | `cisco.ftd.security_event.destination_ip_dynamic_attribute` | keyword | Destination IP dynamic attribute (EPG info) |
| `DestinationSecurityGroup` | `cisco.ftd.security_event.destination_security_group` | keyword | Security Group of the destination |
| `DestinationSecurityGroupTag` | `cisco.ftd.security_event.destination_security_group_tag` | keyword | Numeric SGT attribute of destination |

## Changes Made

### 1. Ingest Pipeline ([default.yml](data_stream/log/elasticsearch/ingest_pipeline/default.yml))
- Added 6 field mappings in the script processor params section  
- Added field targets to `security_event_list` array to ensure fields are placed in `cisco.ftd.security_event` group (consistent with other connection event fields)  
- Fields are configured for message IDs `["430002", "430003"]`

### 2. Field Definitions ([fields.yml](data_stream/log/fields/fields.yml))
- Added 6 field definitions under `cisco.ftd.security_event` group  
- All fields typed as `keyword` to support both string and numeric values  
- Added descriptions based on official Cisco documentation

### 3. Testing
- Created new test file [test-sgt.log](data_stream/log/_dev/test/pipeline/test-sgt.log) with 2 sample connection events containing SGT/EGT fields  
- Test covers both 430002 (connection start) and 430003 (connection end) message types  
- Validates extraction of both string values (e.g., `"SGT_TEST_GROUP"`) and numeric values (e.g., `"2005"`)  
- All 39 pipeline tests passing ✅

## Implementation Notes
Fields are placed in `cisco.ftd.security_event` rather than the legacy `cisco.ftd.security` field for consistency and maintainability.  
All new fields use `keyword` type to handle both string and numeric values.

## Testing Performed
- [x] Pipeline tests pass (39/39)  
- [x] Fields extract correctly  
- [x] Correct ECS placement  
- [x] No regressions  

## References
- Issue: #15204  
- Cisco Documentation: [Cisco Secure Firewall Threat Defense Syslog Messages — Connection Event Field Descriptions](https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/security-event-syslog-messages.html#id_87692)  

## Checklist
- [x] Field definitions added  
- [x] Pipeline updated  
- [x] Tests added  
- [x] Docs/links included  
- [x] All tests passing  
