#!/usr/bin/env python3
"""Convert a `trivy k8s cluster --report all --format json` report into the
per-finding NDJSON format the trivy integration ingests.

The cluster report nests findings as Resources[].Results[].Vulnerabilities[]
with no scan-level metadata; the integration expects one line per finding with
scan/resource/artifact/result/vulnerability objects (same shape trivy-operator
emits). This script flattens and reshapes accordingly.

Note: cluster reports contain no scan.hostname, scan.time or trivy_version.
Those are left out unless supplied via --hostname/--scan-time/--trivy-version.

Usage:
  python3 trivy_cluster_to_ndjson.py INPUT.json [-o OUT.ndjson]
"""

import argparse
import json
import sys


def convert(report, hostname=None, scan_time=None, trivy_version=None):
    cluster_name = report.get("ClusterName")
    for resource in report.get("Resources", []):
        kind = resource.get("Kind")
        name = resource.get("Name")
        namespace = resource.get("Namespace")

        # Image metadata; non-image resources (nodes, config) have none.
        metadata = next((m for m in resource.get("Metadata") or [] if m.get("Reference")), None)

        scan = {}
        if cluster_name:
            scan["cluster_name"] = cluster_name
        if hostname:
            scan["hostname"] = hostname
        if scan_time:
            scan["time"] = scan_time
        if trivy_version:
            scan["trivy_version"] = trivy_version

        for result in resource.get("Results") or []:
            vulnerabilities = result.get("Vulnerabilities") or []
            if not vulnerabilities:
                continue

            artifact = None
            if metadata:
                reference = metadata["Reference"]
                artifact = {
                    "ArtifactName": reference,
                    "ArtifactType": "container_image",
                }
                for key in ("OS", "ImageID", "RepoTags", "RepoDigests", "Reference"):
                    if metadata.get(key) is not None:
                        artifact[key] = metadata[key]

            result_out = {
                key: result[key]
                for key in ("Target", "Class", "Type")
                if result.get(key) is not None
            }

            for vuln in vulnerabilities:
                finding = {
                    "scan": scan or None,
                    "resource": {
                        "Namespace": namespace,
                        "Kind": kind,
                        "Name": name,
                    } if kind or name or namespace else None,
                    "artifact": artifact,
                    "result": result_out or None,
                    "vulnerability": vuln,
                }
                yield finding


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", help="trivy k8s cluster JSON report")
    parser.add_argument("-o", "--output", help="output NDJSON file (default: stdout)")
    parser.add_argument("--hostname", help="optional scan.hostname to attach to every finding")
    parser.add_argument("--scan-time", help="optional scan.time (ISO 8601) for every finding")
    parser.add_argument("--trivy-version", help="optional scan.trivy_version for every finding")
    args = parser.parse_args()

    with open(args.input) as f:
        report = json.load(f)

    out = open(args.output, "w") if args.output else sys.stdout
    count = 0
    try:
        for finding in convert(
            report,
            hostname=args.hostname,
            scan_time=args.scan_time,
            trivy_version=args.trivy_version,
        ):
            out.write(json.dumps(finding, separators=(",", ":"), ensure_ascii=False) + "\n")
            count += 1
    finally:
        if args.output:
            out.close()
    print(f"{count} findings written", file=sys.stderr)


if __name__ == "__main__":
    main()
