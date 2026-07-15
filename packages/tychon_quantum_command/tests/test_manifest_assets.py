from __future__ import print_function

import io
import os
import unittest


SCREENSHOTS = [
    ('/img/TQC_Inventory.png', '3434x1086'),
    ('/img/TQC_Application_Report.png', '3437x1072'),
    ('/img/TQC_Application_Detail.png', '3435x1086'),
    ('/img/TQC_Certificate_Report.png', '3437x1083'),
    ('/img/TQC_Application_Connections_Topology.png', '3435x1082'),
    ('/img/TQC_Cost_Analysis.png', '3438x1082'),
]


class ManifestAssetsTest(unittest.TestCase):
    def setUp(self):
        # type: () -> None
        self.package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.manifest_path = os.path.join(self.package_dir, 'manifest.yml')

    def test_manifest_screenshot_files_exist_with_expected_size_metadata(self):
        # type: () -> None
        with io.open(self.manifest_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        for src, size in SCREENSHOTS:
            disk_path = os.path.join(self.package_dir, src.lstrip('/').replace('/', os.sep))
            self.assertTrue(os.path.isfile(disk_path), 'Missing screenshot file %s' % src)
            self.assertIn('src: %s' % src, content)
            self.assertIn('size: %s' % size, content)

        self.assertNotIn('Topography', content)
        self.assertNotIn('Appplication', content)


if __name__ == '__main__':
    unittest.main()