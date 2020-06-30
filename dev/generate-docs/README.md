# Generate docs

The script allows for regenerating README docs based on the existing package content and the `import-beats-resources`
(docs template).

Template for README.md file supports following template functions:

`{{fields "access"}}` - render a table with exported fields for the dataset `access`

`{{event "access"}}` - render a sample event for the dataset `access`. The dataset event must be present in the
`{packageName}/dataset/{datasetName}/sample_event.json` file.

## Getting started

Navigate to the integrations root directory and execute the following command:

```bash
PACKAGES=nginx mage GenerateDocs
```