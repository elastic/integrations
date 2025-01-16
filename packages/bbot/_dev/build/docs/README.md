# BBOT integration

The Bighuge BLS OSINT Tool (BBOT) integration is intended for [BBOT](https://www.blacklanternsecurity.com/bbot/) installations, an Attack Surface Management (ASM) Open Source Inteligence (OSINT) Tool.

Once the BBOT scan is complete, the integration will ingest the results into Elastic.

This tool is used to enhance your external knowledge of your environment. This is done through the integration of many tools into BBOT providing a overview of your attack surface. Here is [how it works](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/).

**Important Note** - You will have to provide the following parameter in your BBOT scan for your output.ndjson to be formatted correctly.
```
-c output_modules.json.siem_friendly=true
```
**Example BBOT Scan**
```
bbot -t elastic.co --strict-scope -f safe passive -c output_modules.json.siem_friendly=true -om json
```

You will have to configure the path for the output file within the integration settings. A common and popular path that could work here is:

**Example BBOT Path**
```
/home/<user>/.bbot/scans/*/output.ndjson
```

BBOT Scanning [Documentation](https://www.blacklanternsecurity.com/bbot/Stable/scanning/).

## Data streams

This integration collects the following logs:

- **asm_intel** Made up of the findings found in the BBOT Scans.

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).


### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `BBOT`.
3. Select the "BBOT" integration from the search results.
4. Select "Add BBOT" to add the integration.
5. Add all the required integration configuration parameters including the Path to ndjson output file.
6. Save the integration.

## Logs

### ASM Findings

{{event "asm_intel"}}

{{fields "asm_intel"}}
