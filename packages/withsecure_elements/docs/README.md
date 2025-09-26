# WithSecure Elements Integration

This integration allows you to collect data from the WithSecure Elements API, including incidents (Broad Context Detections - BCDs) and security events.

## Configuration

### Prerequisites

- WithSecure Elements Client ID and Client Secret
- Organization ID
- Access to WithSecure Elements API

### Input Configuration

#### Incidents (BCDs)
- **URL**: WithSecure Elements API URL (default: https://api.connect.withsecure.com)
- **Client ID**: Client ID for OAuth2 authentication
- **Client Secret**: Client Secret for OAuth2 authentication
- **Organization ID**: Organization identifier
- **Interval**: Collection interval (default: 5m)

#### Security Events
- **URL**: WithSecure Elements API URL (default: https://api.connect.withsecure.com)
- **Client ID**: Client ID for OAuth2 authentication
- **Client Secret**: Client Secret for OAuth2 authentication
- **Organization ID**: Organization identifier
- **Interval**: Collection interval (default: 5m)

#### Incident Detections
- **URL**: WithSecure Elements API URL (default: https://api.connect.withsecure.com)
- **Client ID**: Client ID for OAuth2 authentication
- **Client Secret**: Client Secret for OAuth2 authentication
- **Organization ID**: Organization identifier
- **Incident ID**: Specific Incident ID to collect detections for
- **Interval**: Collection interval (default: 5m)

## Data Collected

### Incidents (BCDs)
- Security incident information
- Status, severity, risk level
- Categories and sources
- Creation and update timestamps
- Comments and assignments

### Security Events
- Real-time security events
- Actions taken (blocked, quarantined, etc.)
- Device and user information
- Technical event details

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

## Support

For any questions or issues, please refer to the WithSecure Elements documentation or contact support.
