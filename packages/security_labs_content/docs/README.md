# Security Labs Content Integration (Beta)

## Overview

The **Security Labs Content** integration provides the security labs contents to be used within elastic security.

This integration is in **beta** and subject to changes. Feedback and contributions are welcome.

## Requirements

- Elastic Stack **8.19.x**, **9.1.x**, or later.
- Kibana with the **Elastic Assistant** plugin enabled.

## Installation

This integration is automatically installed when users visit the **Security Solution** in Kibana. No manual setup is required.

## Usage

1. Navigate to **Security Solution** in Kibana.
2. The security labs content will be used by the security AI assistant

## Developer Guide

Developers updating this integration must regenerate and update the AI prompts in the package:

1. Generate the Security AI Prompts in the Kibana repository:
   ```sh
   cd x-pack/solutions/security/plugins/elastic_assistant
   yarn generate-security-labs-content
   ```
2. Copy the updated prompt files to this package:
   ```sh
   cd packages/security_labs_content/kibana/security_labs_content
   rm ./*.json
   cp $KIBANA_HOME/target/security_labs_content/*.json .
   ```

## Known Issues & Limitations
This integration is currently in beta and subject to change.

## Contributing
Contributions are welcome! If you encounter issues or have suggestions, please open an issue or submit a pull request.

## License
This integration is subject to the Elastic License.
