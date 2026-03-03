# Security AI Prompts Integration (Beta)

## Overview

The **Security AI Prompts** integration provides pre-configured AI-driven security prompts that enhance automated threat detection and response in Elastic Security. These prompts help security analysts generate AI-assisted insights and streamline their investigative workflows.

This integration is in **beta** and subject to changes. Feedback and contributions are welcome.

## Requirements

- Elastic Stack **8.19.x**, **9.1.x**, or later.
- Kibana with the **Elastic Assistant** plugin enabled.

## Installation

This integration is automatically installed when users visit the **Security Solution** in Kibana. No manual setup is required.

## Usage

1. Navigate to **Security Solution** in Kibana.
2. AI-generated security prompts will be used in AI Assistant, Attack Discovery, and other security AI features to assist in investigations and threat analysis.

## Developer Guide

Developers updating this integration must regenerate and update the AI prompts in the package:

1. Generate the Security AI Prompts in the Kibana repository:
   ```sh
   cd x-pack/solutions/security/plugins/elastic_assistant
   yarn generate-security-ai-prompts
   ```
2. Copy the updated prompt files to this package:
   ```sh
   cd packages/security_ai_prompts/kibana/security_ai_prompt
   rm ./*.json
   cp $KIBANA_HOME/target/security_ai_prompts/*.json .
   ```

## Known Issues & Limitations
This integration is currently in beta and subject to change.
Future versions may include automatic prompt synchronization.

## Contributing
Contributions are welcome! If you encounter issues or have suggestions, please open an issue or submit a pull request.

## License
This integration is subject to the Elastic License.
