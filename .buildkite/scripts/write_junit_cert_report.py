#!/usr/bin/env python3
"""Writes a JUnit XML report for TLS certificate expiry failures.

Usage:
    python3 write_junit_cert_report.py <package> <output_path> <cert_path> <message> [<cert_path> <message> ...]

Arguments arrive as cert_path/message pairs. The classname is derived from the
cert path: packages/aws/data_stream/config/_dev/... → "aws.config", and
packages/cybereason/_dev/... → "cybereason". Each pair becomes a testcase with
an <error> element — the JUnit semantic for a setup error that prevented the
test from running, mirroring pytest's "ERROR at setup of <test>" pattern.

Called by check_certificates.sh; do not invoke directly.
"""

import os
import re
import sys
import xml.etree.ElementTree as ET

if os.environ.get("_CERT_CHECK_CALLER") != "check_certificates.sh":
    print("write_junit_cert_report.py must be called from check_certificates.sh", file=sys.stderr)
    sys.exit(1)

def classname_from_path(cert_path, fallback):
    """packages/aws/data_stream/config/_dev/... → 'aws.config'
    packages/cybereason/_dev/...             → 'cybereason'"""
    m = re.search(r"packages/([^/]+)/data_stream/([^/]+)/", cert_path)
    if m:
        return f"{m.group(1)}.{m.group(2)}"
    m = re.search(r"packages/([^/]+)/", cert_path)
    if m:
        return m.group(1)
    return fallback


package = sys.argv[1]
output_path = sys.argv[2]
items = sys.argv[3:]  # interleaved: cert_path, message, cert_path, message, ...

if len(items) % 2 != 0:
    print(f"write_junit_cert_report.py: expected cert_path/message pairs, got {len(items)} argument(s)", file=sys.stderr)
    sys.exit(1)

pairs = [(items[i], items[i + 1]) for i in range(0, len(items), 2)]

testsuites = ET.Element("testsuites")
testsuite = ET.SubElement(testsuites, "testsuite")
testsuite.set("name", "system")
testsuite.set("tests", str(len(pairs)))
testsuite.set("errors", str(len(pairs)))
testsuite.set("failures", "0")

for cert_path, message in pairs:
    testcase = ET.SubElement(testsuite, "testcase")
    testcase.set("name", "certificate expiry check")
    testcase.set("classname", classname_from_path(cert_path, package))
    ET.SubElement(testcase, "error").text = message

tree = ET.ElementTree(testsuites)
try:
    ET.indent(tree, space="  ")
except AttributeError:
    pass  # ET.indent added in Python 3.9

with open(output_path, "w", encoding="utf-8") as f:
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    tree.write(f, encoding="unicode")
    f.write("\n")
