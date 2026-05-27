#!/usr/bin/env python3
"""
Find the directory of a package given its manifest name.

Uses `mage listPackages` to enumerate package directories, then reads each
manifest.yml to find the one whose `name` field matches the given package name.

Usage:
    backport_resolve_package_dir.py --package <name>

Output:
    Prints the package directory path to stdout.

Exit codes:
    0  package found
    1  package not found
    2  usage / dependency error
"""
import argparse
import os
import subprocess
import sys
import unittest


def _list_package_dirs():
    """Return package directories from `mage listPackages`."""
    result = subprocess.run(
        ["mage", "listPackages"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def find_package_dir(package_name, package_dirs=None):
    try:
        import yaml
    except ImportError:
        print("PyYAML is required: pip install pyyaml", file=sys.stderr)
        sys.exit(2)

    if package_dirs is None:
        package_dirs = _list_package_dirs()

    for pkg_dir in package_dirs:
        manifest = os.path.join(pkg_dir, "manifest.yml")
        try:
            with open(manifest) as f:
                data = yaml.safe_load(f) or {}
            if data.get("name") == package_name:
                return pkg_dir
        except Exception:
            continue

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Find a package directory by its manifest name."
    )
    parser.add_argument("--package", metavar="NAME", help="Package name as defined in manifest.yml")
    parser.add_argument("--test",    action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    if not args.package:
        parser.error("--package is required")

    pkg_dir = find_package_dir(args.package)
    if pkg_dir is None:
        print(f"Package '{args.package}' not found in packages/", file=sys.stderr)
        sys.exit(1)

    print(pkg_dir)


# ── tests ─────────────────────────────────────────────────────────────────────

class TestFindPackageDir(unittest.TestCase):

    def setUp(self):
        import pathlib
        import tempfile
        self._tmp = pathlib.Path(tempfile.mkdtemp())

        # Folder name matches manifest name
        (self._tmp / "packages" / "aws").mkdir(parents=True)
        (self._tmp / "packages" / "aws" / "manifest.yml").write_text(
            "name: aws\nversion: 6.14.2\n"
        )

        # Folder name differs from the manifest name field
        (self._tmp / "packages" / "my_package_folder").mkdir(parents=True)
        (self._tmp / "packages" / "my_package_folder" / "manifest.yml").write_text(
            "name: my_pkg\nversion: 1.0.0\n"
        )

        # Nested path returned by mage listPackages (e.g. packages/<category>/<pkg>)
        (self._tmp / "packages" / "o11y" / "nginx_metrics").mkdir(parents=True)
        (self._tmp / "packages" / "o11y" / "nginx_metrics" / "manifest.yml").write_text(
            "name: nginx\nversion: 1.10.0\n"
        )

        self._pkg_dirs = [
            str(self._tmp / "packages" / "aws"),
            str(self._tmp / "packages" / "my_package_folder"),
            str(self._tmp / "packages" / "o11y" / "nginx_metrics"),
        ]

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp)

    def test_finds_package_by_manifest_name(self):
        self.assertEqual(
            find_package_dir("aws", package_dirs=self._pkg_dirs),
            str(self._tmp / "packages" / "aws"),
        )

    def test_resolves_by_manifest_name_not_folder_name(self):
        self.assertEqual(
            find_package_dir("my_pkg", package_dirs=self._pkg_dirs),
            str(self._tmp / "packages" / "my_package_folder"),
        )

    def test_nested_package(self):
        self.assertEqual(
            find_package_dir("nginx", package_dirs=self._pkg_dirs),
            str(self._tmp / "packages" / "o11y" / "nginx_metrics"),
        )

    def test_package_not_found_returns_none(self):
        self.assertIsNone(find_package_dir("nonexistent", package_dirs=self._pkg_dirs))


if __name__ == "__main__":
    main()
