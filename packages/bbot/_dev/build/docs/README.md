# BBOT integration

This integration is for [BBOT](https://www.blacklanternsecurity.com/bbot/), an Attack Surface Management (ASM) Open Source Inteligence (OSINT) Tool. BBOT itself stands for Bighuge BLS OSINT Tool (BBOT).

This tool is used to enhance your external knowledge of your environment. This is done through the integration of many tools into BBOT providing a overview of your attack surface. Here is [how it works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

**Important Note** - You will have to provide the following parameter in your BBOT scan for your output.ndjson to be formatted correctly.
```
-c output_modules.json.siem_friendly=true
```
**Example BBOT Scan**
```
bbot -t elastic.co --strict-scope -f safe passive -c output_modules.json.siem_friendly=true -om json
```
BBOT Scanning [Documentation](https://www.blacklanternsecurity.com/bbot/scanning/).

- `bbot` dataset: Made up of the findings found in the BBOT Scans.

## Logs

### ASM Findings

{{event "asm_intel"}}

{{fields "asm_intel"}}
