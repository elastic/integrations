#!/usr/bin/env python3
"""Static columnar-readiness audit for Elastic integration packages.

Scans a package (or the whole catalog) for mapping features that Elasticsearch
rejects or silently degrades under the `logsdb_columnar` index mode, and proposes
an index sort key per data stream.

Usage, from the root of the integrations repository (<skill-dir> is the directory
of the columnar-readiness skill, e.g. .agents/skills/columnar-readiness in the repo,
or wherever `npx skills add` installed it):
    python3 <skill-dir>/scripts/audit.py packages/nginx                 # one package
    python3 <skill-dir>/scripts/audit.py packages/nginx --format json   # one package, JSON
    python3 <skill-dir>/scripts/audit.py packages/ --catalog            # whole catalog
    python3 <skill-dir>/scripts/audit.py packages/ --catalog --format json --out report.json

Requires: Python 3.8+ and PyYAML.
    python3 -m pip install --user pyyaml
    # or, without touching the system interpreter:
    python3 -m venv /tmp/columnar-venv && /tmp/columnar-venv/bin/pip install pyyaml
    /tmp/columnar-venv/bin/python3 <skill-dir>/scripts/audit.py packages/nginx

Scope: logs data streams only. Metrics/traces/synthetics streams, streams fed by an
OpenTelemetry input and `type: input` packages are reported as OUT_OF_SCOPE and
skipped.

Also read, when present:
  * the prebuilt detection rules shipped in `packages/security_detection_engine`
    (the sibling of the audited package; override with `--rules DIR`, skip with
    `--no-rules`), to find rules that read a stream's `_source` and to list the rules
    that query it;
  * elastic-package's ECS cache (`~/.elastic-package/cache/fields/ecs/`), for the
    types of `external: ecs` fields. Without it a small built-in list is used and the
    report says so.

The checks live in the `columnar_readiness` package next to this script; this file
only parses the command line and writes the report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, List, Optional

from columnar_readiness.constants import STATUS_ORDER
from columnar_readiness.ecs import ecs_source
from columnar_readiness.packages import audit_package
from columnar_readiness.report import md_catalog, md_package
from columnar_readiness.rules import RULES_PACKAGE


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("path", help="package directory, or the packages/ root with --catalog")
    parser.add_argument("--catalog", action="store_true",
                        help="treat PATH as a directory of packages and print a catalog summary")
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="markdown")
    parser.add_argument("--out", help="write the report to this file instead of stdout")
    parser.add_argument("--status", action="append",
                        help="in catalog mode, only list packages with this status (repeatable)")
    parser.add_argument("--dashboards", dest="dashboards", action="store_true", default=None,
                        help="scan kibana/ assets for sort tie-breaks (default: on for a single "
                             "package, off for --catalog)")
    parser.add_argument("--no-dashboards", dest="dashboards", action="store_false")
    parser.add_argument("--rules", metavar="DIR",
                        help="directory of detection rule saved objects to scan (default: "
                             f"the `{RULES_PACKAGE}` package next to the audited package)")
    parser.add_argument("--no-rules", dest="no_rules", action="store_true",
                        help="do not scan detection rules")
    parser.add_argument("--detection-rules", metavar="DIR",
                        help="elastic/detection-rules checkout whose `rules/` and `hunting/` "
                             "are scanned for `_source` readers (default: "
                             "$DETECTION_RULES_PATH, then a `detection-rules` checkout next "
                             "to this repository)")
    args = parser.parse_args(argv)

    scan_dashboards = (not args.catalog) if args.dashboards is None else args.dashboards
    rules_dir: Optional[str] = None if args.no_rules else (args.rules or "auto")
    if args.rules and not os.path.isdir(args.rules):
        print(f"error: --rules {args.rules}: not a directory", file=sys.stderr)
        return 2
    if args.detection_rules and not os.path.isdir(os.path.join(args.detection_rules, "rules")):
        print(f"error: --detection-rules {args.detection_rules}: no `rules/` directory; pass "
              f"an elastic/detection-rules checkout", file=sys.stderr)
        return 2

    path = os.path.abspath(args.path.rstrip("/") or args.path)
    if not os.path.isdir(path):
        print(f"error: {args.path}: not a directory", file=sys.stderr)
        return 2

    if args.catalog:
        root = path
        pkg_dirs = [os.path.join(root, d) for d in sorted(os.listdir(root))
                    if os.path.isfile(os.path.join(root, d, "manifest.yml"))]
        if not pkg_dirs:
            print(f"error: {args.path}: no packages (sub-directories with a manifest.yml); "
                  f"pass the packages/ root with --catalog", file=sys.stderr)
            return 2
        results = [audit_package(p, scan_dashboards, rules_dir, args.detection_rules)
                   for p in pkg_dirs]
        if args.status:
            wanted = {s.upper() for s in args.status}
            results_out = [r for r in results if r["status"] in wanted]
        else:
            results_out = results
        md = md_catalog(results_out, scanned=len(results),
                        only=sorted({s.upper() for s in args.status}) if args.status else None)
        payload: Any = {
            "mode": "catalog",
            "root": root,
            "ecs_schema_source": ecs_source(),
            "packages": results_out,
            "summary": {
                "scanned": len(results),
                "by_status": {s: sorted(r["package"] for r in results if r["status"] == s)
                              for s in STATUS_ORDER},
            },
        }
    else:
        if not os.path.isfile(os.path.join(path, "manifest.yml")):
            print(f"error: {args.path}: no manifest.yml; pass a package directory, or the "
                  f"packages/ root with --catalog", file=sys.stderr)
            return 2
        result = audit_package(path, scan_dashboards, rules_dir, args.detection_rules)
        result["ecs_schema_source"] = ecs_source()
        md = md_package(result)
        payload = result

    chunks = []
    if args.format in ("markdown", "both"):
        chunks.append(md)
    if args.format in ("json", "both"):
        chunks.append(json.dumps(payload, indent=2, sort_keys=False))
    text = "\n\n".join(chunks)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
