#!/usr/bin/env python3
"""Writes a JUnit XML report for TLS certificate expiry failures.

Usage:
    python3 write_junit_cert_report.py <package> <output_path> <error_message> [<error_message> ...]

Each error message becomes a testcase with an <error> element — the JUnit
semantic for a setup error that prevented the test from running. This mirrors
how pytest reports "ERROR at setup of <test>" in JUnit XML, and signals in
the Buildkite annotation that the failure occurred before the test could start
rather than being a test assertion failure (<failure>).

Called by check_certificates.sh; do not invoke directly.
"""

import os
import sys
import xml.etree.ElementTree as ET

if os.environ.get("_CERT_CHECK_CALLER") != "check_certificates.sh":
    print("write_junit_cert_report.py must be called from check_certificates.sh", file=sys.stderr)
    sys.exit(1)

package = sys.argv[1]
output_path = sys.argv[2]
error_messages = sys.argv[3:]

testsuites = ET.Element("testsuites")
testsuite = ET.SubElement(testsuites, "testsuite")
testsuite.set("name", "system")
testsuite.set("tests", str(len(error_messages)))
testsuite.set("errors", str(len(error_messages)))
testsuite.set("failures", "0")

for message in error_messages:
    testcase = ET.SubElement(testsuite, "testcase")
    testcase.set("name", "certificate expiry check")
    testcase.set("classname", package)
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
