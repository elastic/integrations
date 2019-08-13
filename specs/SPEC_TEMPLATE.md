# Integration Specification: <name here>

```
Code blocks used for template description -- to be removed when filled

For each integration, create a specification document based on this template.
Use the integration name as a file name: e.g. kafka.md

Use this section for any generic information relevant to the integration
```

## Scope

```
Describe of the expected scope of the integration: logging, metrics, etc. In case the surface area is too big, scope can be narrowed to certain areas and / or split into different milestones.
```

### Milestone 1

```
If more than one milestone is required, just repeat the section. Remove the subsections that do not apply.
```

#### Target

```
Describe the target system versions to support and in which operating systems.
```

#### Logs

```
Whether log capabilities are included. If the target system provides multiple log streams, specify which of them should be included, as well as any special requirement related to log handling.
```

#### Metric sets

```
For each metricset: goal a brief description and metrics to include.
```

#### Dashboards

```
For each dashboard: goal, description, and a rough description of the information to include.
```

## Technical Approach

```
This section describes the technical approach to use to implement the integration.
```

## Decision Log

```
Specification documents are live. This section must contain the record of every decision taken changing the scope or technical approach of the integration (as the section above should always contain the current agreed upon scope). E.g., removing some metrics because they cannot be collected in an efficient way, moving some features to a later milestone because they depend on other developments, etc.

Conversations that can impact the technical approach and / or scope may happen in PRs to the document or offline, but the final decision and rationale should be recorded here. 
```

