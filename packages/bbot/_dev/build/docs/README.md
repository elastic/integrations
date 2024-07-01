# BBOT integration

Please read this page in its entirety as this integration requires some setup.

This integration is for [BBOT](https://www.blacklanternsecurity.com/bbot/), an Attack Surface Management (ASM) Open Source Inteligence (OSINT) Tool. BBOT itself stands for Bighuge BLS OSINT Tool (BBOT).

This integration requires the external use of BBOT. You will have to download and run the tool apart from this integration. Once your scan is complete, this integration will ingest the results into Elastic.

This tool is used to enhance your external knowledge of your environment. This is done through the integration of many tools into BBOT providing a overview of your attack surface. Here is [how it works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

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

BBOT Scanning [Documentation](https://www.blacklanternsecurity.com/bbot/scanning/).

- `bbot` dataset: Made up of the findings found in the BBOT Scans.

## Logs

### ASM Findings

{{event "asm_intel"}}

{{fields "asm_intel"}}
