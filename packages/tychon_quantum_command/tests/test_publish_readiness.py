from __future__ import print_function

import io
import json
import os
import unittest


class PublishReadinessTest(unittest.TestCase):
    def setUp(self):
        # type: () -> None
        self.package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.docs_dir = os.path.join(self.package_dir, 'docs')
        self.dev_dir = os.path.join(self.package_dir, '_dev')
        self.sample_event_path = os.path.join(self.package_dir, 'sample_event.json')
        self.validation_path = os.path.join(self.package_dir, 'validation.yml')

    def test_package_sample_event_is_real_data(self):
        # type: () -> None
        with io.open(self.sample_event_path, 'r', encoding='utf-8') as handle:
            sample_event = json.load(handle)

        self.assertNotIn('description', sample_event)
        self.assertEqual('logs', sample_event['data_stream']['type'])
        self.assertEqual('tychon_quantum_command.tychon_pqc', sample_event['data_stream']['dataset'])
        self.assertEqual('tychon_quantum_command.tychon_pqc', sample_event['event']['dataset'])
        self.assertIn('@timestamp', sample_event)
        self.assertIn('tychon', sample_event)

    def test_validation_enforces_docs_structure(self):
        # type: () -> None
        with io.open(self.validation_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('docs_structure_enforced:', content)
        self.assertIn('enabled: true', content)
        self.assertIn('version: 1', content)
        self.assertIn('exclude_checks: [ "SVR00002" ]', content)

    def test_docs_directory_contains_only_generated_readme(self):
        # type: () -> None
        markdown_files = []
        for file_name in os.listdir(self.docs_dir):
            if file_name.lower().endswith('.md'):
                markdown_files.append(file_name)

        self.assertEqual(['README.md'], sorted(markdown_files))

    def test_dev_directory_contains_only_build_readme_template(self):
        # type: () -> None
        allowed_files = set([
            '_dev/build/docs/README.md',
        ])
        found_files = set()

        for root, _, files in os.walk(self.dev_dir):
            for file_name in files:
                relative_path = os.path.relpath(os.path.join(root, file_name), self.package_dir)
                found_files.add(relative_path.replace('\\', '/'))

        self.assertEqual(allowed_files, found_files)


if __name__ == '__main__':
    unittest.main()
