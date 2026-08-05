#!/bin/env python3
import argparse
import requests
import sys
import unittest
import yaml

from requests.adapters import HTTPAdapter, Retry

ARTIFACTS_URL = "https://artifacts-api.elastic.co"
VERSION_URL = ARTIFACTS_URL + "/v1/versions?x-elastic-no-kpi=true"


def fetch_version():
    # Retry forever on connection or 500 errors, assume the artifacts API
    # will come back. If it doesn't come back we cannot continue executing
    # jobs in any case.
    retries = Retry(
        total=None,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    session = requests.Session()
    session.mount(ARTIFACTS_URL, HTTPAdapter(max_retries=retries))
    return session.get(VERSION_URL).json()


def find_oldest_supported_version(kibana_version_condition: str) -> str:
    if "||" in kibana_version_condition and kibana_version_condition.index("||") >= 0:
        return handle_or(kibana_version_condition)

    artifacts_versions = fetch_version()
    available_versions = artifacts_versions.get("versions", [])
    available_aliases = artifacts_versions.get("aliases", [])
    version = remove_operator(kibana_version_condition)
    parts = version.split(".")

    # If this is specifying a major or a minor only, check with the zero version.
    while len(parts) < 3:
        version += ".0"
        parts.append("0")

    major, minor, patch = parts[0], parts[1], parts[2]

    # Use the snapshot if this is the last patch version.
    next_patch = ".".join((major, minor, str(int(patch)+1)))
    next_patch_exists = (
        next_patch in available_versions or
        f"{next_patch}-SNAPSHOT" in available_versions
    )

    snapshot_version = f"{version}-SNAPSHOT"
    if not next_patch_exists and (snapshot_version in available_versions):
        return snapshot_version

    return version


def remove_operator(kibana_version_condition: str) -> str:
    if kibana_version_condition[0].isdigit():
        return kibana_version_condition
    elif kibana_version_condition.startswith("^") or kibana_version_condition.startswith("~"):
        return kibana_version_condition[1:]
    elif kibana_version_condition.startswith(">="):
        return kibana_version_condition[2:]
    raise Exception("kibana version condition supports only ^, ~ and >= operators")


def handle_or(kibana_version_condition: str):
    if "||" not in kibana_version_condition:
        raise Exception(f"no conditions found in '{kibana_version_condition}'")

    conditions = kibana_version_condition.split("||")
    result = ""
    for cond in conditions:
        candidate = find_oldest_supported_version(cond.strip())
        if result == "" or candidate < result:
            result = candidate

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare Elastic stack")
    parser.add_argument("--manifest-path",
                        required=False,
                        default="manifest.yml",
                        help="path of manifest file")
    parser.add_argument("--test",
                        required=False,
                        action="store_true",
                        default=False,
                        help="trigger test")

    args, unknown = parser.parse_known_args()
    # Set this for unittest
    sys.argv[1:] = unknown
    return args


def run(cfg: argparse.Namespace):
    with open(cfg.manifest_path, "r") as src:
        manifest_doc = yaml.safe_load(src)

    kibana_version_condition = ""
    if "kibana.version" in manifest_doc["conditions"]:
        kibana_version_condition = manifest_doc["conditions"]["kibana.version"]
    elif "kibana" in manifest_doc["conditions"]:
        kibana_version_condition = manifest_doc["conditions"]["kibana"]["version"]

    if kibana_version_condition:
        print(find_oldest_supported_version(kibana_version_condition), end="")
    else:
        print("null")


def main():
    cfg = parse_args()

    if cfg.test:
        unittest.main()
    else:
        run(cfg)


# Test: meant to run locally with --test

class TestFindOldestSupportVersion(unittest.TestCase):
    """Testcase for find_oldest_supported_version."""

    mock_data = {
        "versions": [
            "7.17.10",
            "7.17.11",
            "7.17.12",
            "7.17.13-SNAPSHOT",
            "7.17.13",
            "7.17.14-SNAPSHOT",
            "8.7.0",
            "8.7.1",
            "8.8.0",
            "8.8.1",
            "8.8.2",
            "8.9.1-SNAPSHOT",
            "8.9.1",
            "8.9.2-SNAPSHOT",
            "8.9.2",
            "8.9.4",
            "8.10.0-SNAPSHOT",
            "8.10.0",
            "8.10.1-SNAPSHOT",
            "8.10.1",
            "8.11.0-SNAPSHOT"
        ],
        "aliases": [
            "7.x-SNAPSHOT",
            "7.17-SNAPSHOT",
            "7.17",
            "8.x-SNAPSHOT",
            "8.7",
            "8.8",
            "8.9-SNAPSHOT",
            "8.9",
            "8.10-SNAPSHOT",
            "8.10",
            "8.11-SNAPSHOT"
        ],
        "manifests": {
            "last-update-time": "Thu, 14 Sep 2023 16:03:46 UTC",
            "seconds-since-last-update": 107
        }
    }

    def setUp(self):
        super().setUp()
        global fetch_version
        self._fetch_version = fetch_version
        def fetch_version(): return self.mock_data

    def tearDown(self):
        global fetch_version
        fetch_version = self._fetch_version
        super().tearDown()

    def test_next_patch_does_not_exits_and_available_version_contains_snapshot(self):
        self.assertEqual(find_oldest_supported_version("7.17.14"), "7.17.14-SNAPSHOT")
        self.assertEqual(find_oldest_supported_version("8.9.2"), "8.9.2-SNAPSHOT")
        self.assertEqual(find_oldest_supported_version("8.10.1"), "8.10.1-SNAPSHOT")
        self.assertEqual(find_oldest_supported_version("8.11.0"), "8.11.0-SNAPSHOT")

    def test_available_version_contains_kibana_version(self):
        self.assertEqual(find_oldest_supported_version("7.17.10"), "7.17.10")
        self.assertEqual(find_oldest_supported_version("7.17.11"), "7.17.11")
        self.assertEqual(find_oldest_supported_version("7.17.12"), "7.17.12")
        self.assertEqual(find_oldest_supported_version("7.17.13"), "7.17.13")
        self.assertEqual(find_oldest_supported_version("8.7.1"), "8.7.1")
        self.assertEqual(find_oldest_supported_version("8.10.0"), "8.10.0")

    def test_too_old_to_be_in_api(self):
        self.assertEqual(find_oldest_supported_version("7.16.0"), "7.16.0")
        self.assertEqual(find_oldest_supported_version("8.6.0"), "8.6.0")
        self.assertEqual(find_oldest_supported_version("7.6.0"), "7.6.0")

    def test_newer_major_or_minor_versions_not_shown_in_api(self):
        # next minor from 7.x
        self.assertEqual(find_oldest_supported_version("7.19.0"), "7.19.0")
        # next minor from 8.x
        self.assertEqual(find_oldest_supported_version("8.12.0"), "8.12.0")
        # next patch from 8.8.x
        self.assertEqual(find_oldest_supported_version("8.8.3"), "8.8.3")
        # next major 9.0
        self.assertEqual(find_oldest_supported_version("9.0.0"), "9.0.0")

    def test_missing_older_versions_in_api_response(self):
        # exists 8.9.1 and 8.8.x, but not 8.9.0
        self.assertEqual(find_oldest_supported_version("8.9.0"), "8.9.0")
        # exists 8.9.2 and 8.9.4, but not 8.9.3
        self.assertEqual(find_oldest_supported_version("8.9.3"), "8.9.3")

    def test_or(self):
        self.assertEqual(find_oldest_supported_version("8.6.0||8.7.0"), "8.6.0")
        self.assertEqual(find_oldest_supported_version("8.9.2||8.9.1||7.17.14"), "7.17.14-SNAPSHOT")

    def test_mix(self):
        self.assertEqual(find_oldest_supported_version("^8.6.0||~8.7.0"), "8.6.0")
        self.assertEqual(find_oldest_supported_version("8.9.2||8.9.1||7.17.14"), "7.17.14-SNAPSHOT")
        self.assertEqual(find_oldest_supported_version(
            "~8.9.2||>=8.11.0||7.17.14"), "7.17.14-SNAPSHOT")

    def test_whitespaces(self):
        self.assertEqual(find_oldest_supported_version(" ^8.6.0 || ~8.7.0 "), "8.6.0")


class TestRemoveOperator(unittest.TestCase):
    """Testcase for remove_operator."""

    def test_no_operator(self):
        self.assertEqual(remove_operator("1.0.0"), "1.0.0")

    def test_circumflex(self):
        self.assertEqual(remove_operator("^1.0.0"), "1.0.0")

    def test_tilda(self):
        self.assertEqual(remove_operator("~1.0.0"), "1.0.0")

    def test_greater_or_equal(self):
        self.assertEqual(remove_operator(">=1.0.0"), "1.0.0")

    def test_unknown(self):
        with self.assertRaises(Exception):
            remove_operator("<=1.0.0")
        with self.assertRaises(Exception):
            remove_operator("==1.0.0")


class TestHandleOr(unittest.TestCase):
    """Testcase for handle_or."""

    def test_single_condition(self):
        with self.assertRaises(Exception):
            handle_or("0.0.1")

    def test_happy_path(self):
        # Mock temporarly with the identiy function.
        global find_oldest_supported_version
        old_func = find_oldest_supported_version
        def find_oldest_supported_version(x): return x

        self.assertEqual(handle_or("0.1||0.2"), "0.1")
        self.assertEqual(handle_or("0.2||0.2.1||0.2.3-alpha"), "0.2")
        self.assertEqual(handle_or("1.2||1.2.0||3.2.3-alpha"), "1.2")

        # restore mock
        find_oldest_supported_version = old_func


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
