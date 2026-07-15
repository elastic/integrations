from __future__ import print_function

import io
import os
import re
import unittest


class ChangelogTest(unittest.TestCase):
    def setUp(self):
        # type: () -> None
        self.package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.changelog_path = os.path.join(self.package_dir, 'changelog.yml')

    def test_every_change_entry_has_link(self):
        # type: () -> None
        with io.open(self.changelog_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        change_entries = re.findall(r'(?ms)^    - description: .*?(?=^    - description: |\Z)', content)
        self.assertGreaterEqual(len(change_entries), 1)

        for entry in change_entries:
            self.assertRegex(entry, r'(?m)^      link: https?://\S+$')


if __name__ == '__main__':
    unittest.main()