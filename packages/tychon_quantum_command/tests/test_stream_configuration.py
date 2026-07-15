from __future__ import print_function

import io
import os
import re
import unittest


class StreamConfigurationTest(unittest.TestCase):
    def setUp(self):
        # type: () -> None
        self.package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.manifest_path = os.path.join(
            self.package_dir,
            "data_stream",
            "tychon_pqc",
            "manifest.yml",
        )
        self.stream_template_path = os.path.join(
            self.package_dir,
            "data_stream",
            "tychon_pqc",
            "agent",
            "stream",
            "stream.yml.hbs",
        )
        self.pipeline_path = os.path.join(
            self.package_dir,
            "data_stream",
            "tychon_pqc",
            "elasticsearch",
            "ingest_pipeline",
            "default.yml",
        )
        self.ecs_fields_path = os.path.join(
            self.package_dir,
            "data_stream",
            "tychon_pqc",
            "fields",
            "ecs.yml",
        )
        self.custom_fields_path = os.path.join(
            self.package_dir,
            "data_stream",
            "tychon_pqc",
            "fields",
            "fields.yml",
        )
        self.transform_dir = os.path.join(
            self.package_dir,
            "elasticsearch",
            "transform",
        )

    def _read_text(self, path):
        # type: (str) -> str
        with io.open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_manifest_exposes_windows_and_linux_path_vars(self):
        # type: () -> None
        content = self._read_text(self.manifest_path)

        self.assertIn("- name: windows_paths", content)
        self.assertIn("title: Windows paths", content)
        self.assertIn(r"C:\Program Files\Tychon\*.ndjson", content)

        self.assertIn("- name: linux_paths", content)
        self.assertIn("title: Linux paths", content)
        self.assertIn("/var/log/tychon/*.ndjson", content)

        additional_paths_match = re.search(
            r"- name: paths\s+type: text\s+title: Additional paths\s+multi: true\s+required: false",
            content,
            re.MULTILINE,
        )
        self.assertIsNotNone(additional_paths_match)

    def test_stream_template_renders_all_path_groups(self):
        # type: () -> None
        content = self._read_text(self.stream_template_path)

        self.assertNotIn("type: filestream", content)
        self.assertNotIn("id:", content)
        self.assertNotIn("data_stream:", content)
        self.assertNotIn("{{uuid}}", content)
        self.assertNotIn("{{data_stream.type}}-{{data_stream.dataset}}", content)
        self.assertIn("parsers:", content)
        self.assertIn("ndjson:", content)
        self.assertIn("overwrite_keys: true", content)
        self.assertIn("expand_keys: true", content)

        expected_order = [
            "{{#each windows_paths}}",
            "{{#each linux_paths}}",
            "{{#each paths}}",
        ]

        start = 0
        for marker in expected_order:
            index = content.find(marker, start)
            self.assertNotEqual(-1, index, "Missing marker %s" % marker)
            start = index + 1

    def test_ingest_pipeline_preserves_or_derives_event_dataset(self):
        # type: () -> None
        content = self._read_text(self.pipeline_path)

        self.assertNotIn("field: event.dataset\n      value: tychon_pqc", content)
        self.assertIn("currentDataset == null", content)
        self.assertIn("currentDataset == 'tychon_quantum_command.tychon_pqc'", content)
        self.assertIn("currentDataset == 'tychon_pqc'", content)
        self.assertIn("dataset = 'tychon.application';", content)
        self.assertIn("dataset = 'tychon.installed_app';", content)
        self.assertIn("dataset = 'tychon.browser_extension';", content)
        self.assertIn("dataset = 'tychon.cipher';", content)
        self.assertIn("tychonIndex == 'system-readiness'", content)
        self.assertIn("def eventAction = ctx.event.action != null ? ctx.event.action.toString() : null;", content)
        self.assertIn("if (eventAction == 'quantum_assessment_app_group') {", content)
        self.assertIn("dataset = 'quantum_assessment.app_group';", content)
        self.assertIn("dataset = 'quantum_assessment';", content)
        self.assertIn("currentDataset == genericDataset", content)
        self.assertIn("currentDataset instanceof List && currentDataset.contains(genericDataset)", content)
        self.assertIn("genericDataset = tychonIndex != null ? 'tychon_quantum_command.' + tychonIndex : null;", content)

    def test_ingest_pipeline_includes_reference_rehydration_and_flat_field_logic(self):
        # type: () -> None
        content = self._read_text(self.pipeline_path)

        self.assertIn("field: event.ingested", content)
        self.assertIn("Preserve flat event.* fields before event defaults are applied.", content)
        self.assertIn("ctx.event.dataset = ctx['event.dataset'];", content)
        self.assertIn("ctx.remove('event.dataset');", content)
        self.assertLess(content.find("ctx.event.dataset = ctx['event.dataset'];"), content.find("def shouldDeriveDataset"))
        self.assertIn("- dot_expander:", content)
        self.assertIn("field: tychon.pipeline.processed", content)
        self.assertIn("field: tychon.pipeline.failed", content)
        self.assertIn("field: tychon.routing.original.host_ip", content)
        self.assertIn("field: tychon.routing.target.ip", content)
        self.assertIn("ctx.tychon.certificate_leaf_details = leafDetails;", content)
        self.assertNotIn("certificate.leaf", content)
        self.assertIn("ctx.tychon.cipher_negotiation = cipherNeg;", content)
        self.assertIn("field: x509.issuer.organization", content)
        self.assertIn("{{certificate.subject_public_key_info.curve}}", content)
        self.assertIn("field: certificate.not_before", content)
        self.assertIn("field: certificate.not_after", content)
        self.assertIn("field: x509.subject.organization", content)
        self.assertIn("field: x509.public_key_curve", content)
        self.assertIn("field: destination.address", content)
        self.assertIn("field: source.user.id", content)
        self.assertIn("field: host.domain", content)
        self.assertIn("field: network.protocol", content)
        self.assertIn("{{port.protocol_detected}}", content)
        self.assertIn("{{tychon.application.protocol_detected}}", content)
        self.assertIn("field: error.processor_type", content)
        self.assertIn("field: error.processor_tag", content)
        self.assertIn("field: error.pipeline", content)
        self.assertIn("ctx?.event?.dataset == 'quantum_assessment.app_group'", content)
        self.assertIn("costAnalysis.instance_count = 1;", content)
        self.assertNotIn("costAnalysis.app_family = costAnalysis.os_upgrade_target;", content)
        self.assertNotIn("costAnalysis.tier = costAnalysis.os_tier;", content)
        self.assertNotIn("costAnalysis.labor_cost_usd = costAnalysis.os_labor_cost_usd;", content)
        self.assertNotIn("costAnalysis.license_cost_usd = costAnalysis.os_license_cost_usd;", content)
        self.assertNotIn("costAnalysis.hardware_cost_usd = costAnalysis.os_hardware_cost_usd;", content)

    def test_field_definitions_cover_rehydrated_pipeline_outputs(self):
        # type: () -> None
        ecs_content = self._read_text(self.ecs_fields_path)
        custom_content = self._read_text(self.custom_fields_path)

        self.assertIn("- name: ingested", ecs_content)
        self.assertIn("- name: address", ecs_content)
        self.assertIn("- name: pipeline", ecs_content)
        self.assertIn("- name: processor_tag", ecs_content)
        self.assertIn("- name: processor_type", ecs_content)
        self.assertIn("- name: ipv4", ecs_content)
        self.assertIn("- name: ipv6", ecs_content)
        self.assertIn("- name: domain", ecs_content)
        self.assertIn("- name: network", ecs_content)
        self.assertIn("- name: protocol", ecs_content)
        self.assertIn("- name: source", ecs_content)
        self.assertIn("- name: id", ecs_content)

        self.assertIn("- name: pipeline", custom_content)
        self.assertIn("- name: processed", custom_content)
        self.assertIn("- name: failed", custom_content)
        self.assertIn("- name: routing", custom_content)
        self.assertIn("- name: cipher_negotiation", custom_content)
        self.assertIn("- name: crypto_libraries", custom_content)
        self.assertIn("- name: public_key_curve", custom_content)
        self.assertIn("- name: organization", custom_content)
        self.assertIn("- name: not_before", custom_content)
        self.assertIn("- name: not_after", custom_content)
        self.assertIn("- name: app_family", custom_content)
        self.assertIn("- name: tier", custom_content)
        self.assertIn("- name: instance_count", custom_content)
        self.assertIn("- name: labor_cost_usd", custom_content)
        self.assertIn("- name: license_cost_usd", custom_content)
        self.assertIn("- name: hardware_cost_usd", custom_content)

    def test_transforms_use_namespace_safe_source_index(self):
        # type: () -> None
        expected_source_index = "index: logs-tychon_quantum_command.tychon_pqc-*"

        for transform_name in os.listdir(self.transform_dir):
            transform_path = os.path.join(
                self.transform_dir,
                transform_name,
                "transform.yml",
            )

            if not os.path.isfile(transform_path):
                continue

            content = self._read_text(transform_path)

            self.assertIn(
                expected_source_index,
                content,
                "Transform %s must read from every namespace." % transform_name,
            )
            self.assertNotIn(
                "index: logs-tychon_quantum_command.tychon_pqc-default",
                content,
                "Transform %s still hardcodes the default namespace." % transform_name,
            )


if __name__ == "__main__":
    unittest.main()
