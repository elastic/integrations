# Docs Validator

This script validates the `system_info.md` knowledge-base markdown file by:

1.  Reading the markdown file and extracting URLs.
2.  Validating the URLs.
3.  Validating the markdown file's format against a template.

## Installation

This project uses `uv` for package management. To install the dependencies, run:

```bash
uv venv && uv sync
```

## Usage

To run the script, execute the `validate.py` file:

```bash
uv run validate.py
```

## Environment Variables

The script uses the following environment variables:

*   `MODEL`: The model to use for the AI agents. Defaults to `google-gla:gemini-2.5-flash`.
*   `INTEGRATIONS_REPO_PATH`: The path to the integrations repository. Defaults to the parent directory of the script.
*   `PACKAGE_NAME`: The name of the package to validate. Defaults to `cisco_ftd`.
