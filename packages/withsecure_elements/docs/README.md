# WithSecure Elements Integration

This integration allows you to collect data from the WithSecure Elements API, including incidents (Broad Context Detections - BCDs) and security events.

## Configuration

### Prerequisites

- WithSecure Elements Client ID and Client Secret
- Organization ID
- Access to WithSecure Elements API

### Input Configuration

This integration uses a **single input configuration** for all data streams. You only need to configure the API credentials once:

- **URL**: WithSecure Elements API URL (default: https://api.connect.withsecure.com)
- **Client ID**: Client ID for OAuth2 authentication
- **Client Secret**: Client Secret for OAuth2 authentication
- **Organization ID**: Organization identifier

### Data Streams

You can enable/disable each data stream individually. Each data stream has its own collection interval:

#### Incidents (BCDs)
Collects Broad Context Detections (BCDs) from WithSecure Elements API.
- **Interval**: Collection interval (default: 5m)
- **API Endpoint**: `GET /incidents/v1/incidents`
- **Max items per request**: 50

#### Security Events
Collects security events from WithSecure Elements API (EPP and EDR engines).
- **Interval**: Collection interval (default: 5m)
- **API Endpoint**: `POST /security-events/v1/security-events`
- **Max items per request**: 200
- **Engines**: EPP (Endpoint Protection) and EDR (Detection and Response)

#### Incident Detections (Optional - Disabled by default)
Collects detections for specific incidents from WithSecure Elements API.
- **Incident ID**: Specific Incident ID to collect detections for
- **Interval**: Collection interval (default: 5m)
- **Note**: Requires a valid incident ID. Enable this data stream only if you need detections for specific incidents.

## Data Collected

### Incidents (BCDs)
- Security incident information
- Status, severity, risk level
- Categories and sources
- Creation and update timestamps
- Comments and assignments

### Security Events
- Real-time security events from EPP and EDR
- Actions taken (blocked, quarantined, deleted, etc.)
- Device and user information
- Engine-specific details (DeepGuard, Application Control, DataGuard, etc.)
- Severity levels (critical, warning, info)

### Incident Detections
- Detections specific to each incident
- Detailed threat detection information
- Data on files, users, and devices involved
- Network and behavioral information

## ECS Fields

Data is mapped to the Elastic Common Schema (ECS) with the following fields:
- `event.category`: Event category
- `event.type`: Event type
- `event.severity`: Severity level
- `event.action`: Action taken
- `event.provider`: Provider (withsecure_elements)
- `event.id`: Unique event identifier
- `event.created`: Event creation timestamp
- `@timestamp`: Event timestamp

## Authentication

The integration uses OAuth2 client credentials flow for authentication:
- **Token URL**: `{API_URL}/as/token.oauth2`
- **Grant Type**: `client_credentials`
- **Scope**: `connect.api.read`

## Support

For any questions or issues, please refer to the WithSecure Elements documentation or contact support.
