#!/usr/bin/env python3
"""
Check whether a backport branch is active according to .backports.yml.

A branch is inactive if:
  - archived: true, OR
  - maintained_until is set and the date has already passed.

Branches not listed in the inventory are treated as active (newly created
branches may not be registered yet).

Usage:
    backport_check_active.py --branch <name> [--json]

The inventory file defaults to .backports.yml in the current directory and can
be overridden via the INVENTORY_FILE environment variable (useful for tests).

Output (--json):
    {"branch": "...", "active": true, "archived": false, "maintained_until": null}

Exit codes:
    0  active
    1  inactive
    2  usage / dependency error
"""
import argparse
import datetime
import json
import os
import sys
import unittest


def load_inventory(path):
    try:
        import yaml
    except ImportError:
        print("PyYAML is required: pip install pyyaml", file=sys.stderr)
        sys.exit(2)

    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def check_active(branch, inventory_path):
    data  = load_inventory(inventory_path)
    today = datetime.date.today()

    entry = next(
        (b for b in data.get("backports", []) if b.get("branch") == branch),
        None,
    )
    if entry is None:
        return {"branch": branch, "active": True, "archived": False, "maintained_until": None}

    archived = bool(entry.get("archived", False))
    mu       = entry.get("maintained_until")
    past_eol = False

    if not archived and mu is not None:
        try:
            if isinstance(mu, datetime.datetime):
                eol = mu.date()
            elif isinstance(mu, datetime.date):
                eol = mu
            else:
                eol = datetime.date.fromisoformat(str(mu))
            past_eol = eol < today
        except (ValueError, TypeError):
            pass

    active = not archived and not past_eol
    return {
        "branch":           branch,
        "active":           active,
        "archived":         archived,
        "maintained_until": str(mu) if mu is not None else None,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Check whether a backport branch is active in .backports.yml."
    )
    parser.add_argument("--branch", metavar="NAME", help="Backport branch name to check")
    parser.add_argument("--json",   action="store_true", help="Emit structured JSON output")
    parser.add_argument("--test",   action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    if not args.branch:
        parser.error("--branch is required")

    inventory = os.environ.get("INVENTORY_FILE", ".backports.yml")
    result    = check_active(args.branch, inventory)

    if args.json:
        print(json.dumps(result))
    elif not result["active"]:
        mu     = result["maintained_until"]
        reason = "archived" if result["archived"] else f"maintained_until {mu} has passed"
        print(f"Branch {result['branch']} is inactive ({reason})", file=sys.stderr)

    sys.exit(0 if result["active"] else 1)


# ── tests ─────────────────────────────────────────────────────────────────────

_INVENTORY = """\
backports:
  - package: aws
    branch: backport-aws-6.14
    maintained_until: "2027-01-15"
    archived: false
  - package: aws
    branch: backport-aws-3.13
    maintained_until: null
    archived: true
  - package: kubernetes
    branch: backport-kubernetes-1.62
    maintained_until: "2020-01-01"
    archived: false
  - package: nginx
    branch: backport-nginx-1.10
    maintained_until: 2020-01-01T00:00:00
    archived: false
"""


class TestCheckActive(unittest.TestCase):

    def setUp(self):
        import pathlib
        import tempfile
        self._tmp = tempfile.mkdtemp()
        self._inv = str(pathlib.Path(self._tmp) / ".backports.yml")
        pathlib.Path(self._inv).write_text(_INVENTORY)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp)

    def test_active_branch(self):
        r = check_active("backport-aws-6.14", self._inv)
        self.assertTrue(r["active"])
        self.assertFalse(r["archived"])
        self.assertEqual(r["maintained_until"], "2027-01-15")

    def test_archived_branch_is_inactive(self):
        r = check_active("backport-aws-3.13", self._inv)
        self.assertFalse(r["active"])
        self.assertTrue(r["archived"])

    def test_past_eol_branch_is_inactive(self):
        r = check_active("backport-kubernetes-1.62", self._inv)
        self.assertFalse(r["active"])
        self.assertFalse(r["archived"])
        self.assertEqual(r["maintained_until"], "2020-01-01")

    def test_branch_not_in_inventory_is_active(self):
        r = check_active("backport-unknown-1.0", self._inv)
        self.assertTrue(r["active"])
        self.assertIsNone(r["maintained_until"])

    def test_missing_inventory_file_is_active(self):
        r = check_active("backport-aws-6.14", "/nonexistent/.backports.yml")
        self.assertTrue(r["active"])

    def test_json_fields_active(self):
        r = check_active("backport-aws-6.14", self._inv)
        self.assertIn("branch", r)
        self.assertIn("active", r)
        self.assertIn("archived", r)
        self.assertIn("maintained_until", r)

    def test_json_fields_inactive_archived(self):
        r = check_active("backport-aws-3.13", self._inv)
        self.assertFalse(r["active"])
        self.assertTrue(r["archived"])
        self.assertIsNone(r["maintained_until"])

    def test_json_fields_inactive_past_eol(self):
        r = check_active("backport-kubernetes-1.62", self._inv)
        self.assertFalse(r["active"])
        self.assertFalse(r["archived"])
        self.assertEqual(r["maintained_until"], "2020-01-01")

    def test_yaml_timestamp_maintained_until_is_inactive(self):
        # PyYAML parses unquoted timestamps as datetime.datetime; must still be treated as past-EOL.
        r = check_active("backport-nginx-1.10", self._inv)
        self.assertFalse(r["active"])
        self.assertFalse(r["archived"])


if __name__ == "__main__":
    main()
