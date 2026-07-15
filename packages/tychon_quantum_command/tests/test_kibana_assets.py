from __future__ import print_function

import json
import os
import re
import unittest
import zipfile


EXPECTED_COUNTS = {
    "dashboard": 6,
    "index-pattern": 3,
    "search": 2,
    "tag": 3,
    "visualization": 14,
}

TOPOLOGY_VISUALIZATION_ID = 'tychon_quantum_command-bac83eaf-eacf-4a4b-9fb3-aa102b21a34c'
TOPOLOGY_DASHBOARD_ID = 'tychon_quantum_command-6f3d60d5-b5fb-45a5-9298-acf3ceb3ea1b-application-connections-topology'
APPLICATION_REPORT_DASHBOARD_ID = 'tychon_quantum_command-443e5928-b1c4-4e07-b0b9-c675dd057e2f-application-report'
CERTIFICATE_OPERATIONS_DASHBOARD_ID = 'tychon_quantum_command-d0159137-9139-4a93-85bb-2ac9ddab3982-certificate-operations-dashboard'
APPLICATION_LIST_VISUALIZATION_ID = 'tychon_quantum_command-1309bf24-a8af-43cb-8aae-cf88da1db46e'


class KibanaAssetsTest(unittest.TestCase):
    def setUp(self):
        # type: () -> None
        self.package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.kibana_dir = os.path.join(self.package_dir, "kibana")
        self.kibana_zip = os.path.join(self.package_dir, "kibana.zip")

    def _get_source(self):
        # type: () -> str
        for root, _, files in os.walk(self.kibana_dir):
            for file_name in files:
                if file_name.endswith('.json'):
                    return 'dir'
        if os.path.isfile(self.kibana_zip):
            return 'zip'
        self.fail('No Kibana saved objects found in kibana/ or kibana.zip')

    def _load_objects(self):
        # type: () -> tuple
        counts = {}
        objects_by_type = {}

        if self._get_source() == 'dir':
            for root, _, files in os.walk(self.kibana_dir):
                folder_name = os.path.basename(root)
                if folder_name == 'kibana':
                    continue

                normalized_type = folder_name.replace('_', '-')
                for file_name in files:
                    if not file_name.endswith('.json'):
                        continue

                    path = os.path.join(root, file_name)
                    with open(path, 'r', encoding='utf-8') as handle:
                        obj = json.load(handle)

                    counts[normalized_type] = counts.get(normalized_type, 0) + 1
                    type_objects = objects_by_type.setdefault(normalized_type, {})
                    type_objects[obj['id']] = obj

                    self.assertEqual(normalized_type, obj['type'], 'Object type mismatch for %s' % path)
                    self.assertEqual(obj['id'], os.path.splitext(file_name)[0], 'Object filename must exactly match the saved object id for %s' % path)
        else:
            with zipfile.ZipFile(self.kibana_zip, 'r') as archive:
                for name in archive.namelist():
                    if not name.endswith('.json'):
                        continue

                    normalized_name = name.replace('\\', '/')
                    parts = normalized_name.split('/')
                    self.assertGreaterEqual(len(parts), 2, 'Unexpected archive entry %s' % normalized_name)
                    folder_name = parts[0]
                    file_name = parts[-1]
                    normalized_type = folder_name.replace('_', '-')
                    obj = json.loads(archive.read(name).decode('utf-8'))

                    counts[normalized_type] = counts.get(normalized_type, 0) + 1
                    type_objects = objects_by_type.setdefault(normalized_type, {})
                    type_objects[obj['id']] = obj

                    self.assertEqual(normalized_type, obj['type'], 'Object type mismatch for %s' % normalized_name)
                    self.assertEqual(obj['id'], os.path.splitext(file_name)[0], 'Object filename must exactly match the saved object id for %s' % normalized_name)

        return counts, objects_by_type

    def _load_reference_objects(self):
        # type: () -> dict
        reference_path = os.path.join(
            os.path.dirname(self.package_dir),
            "Dashboards",
            "TYCHON QC Enterprise Dashboards 2.0.1.2.ndjson",
        )
        objects_by_type = {}
        with open(reference_path, 'r', encoding='utf-8') as handle:
            for line in handle:
                if not line.strip():
                    continue
                obj = json.loads(line)
                if 'type' not in obj:
                    continue
                type_objects = objects_by_type.setdefault(obj['type'], {})
                type_objects[obj['id']] = obj

        return objects_by_type

    def _reference_dashboard_id(self, dashboard_id):
        # type: (str) -> str
        normalized = dashboard_id
        prefix = 'tychon_quantum_command-'
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]

        for suffix in [
            '-inventory',
            '-application-report',
            '-application-detail',
            '-application-connections-topology',
            '-cost-analysis',
            '-certificate-operations-dashboard',
        ]:
            if normalized.endswith(suffix):
                return normalized[:-len(suffix)]

        return normalized

    def _panel_title(self, panel):
        # type: (dict) -> str
        return (
            panel.get('title') or
            panel.get('embeddableConfig', {}).get('savedVis', {}).get('title') or
            panel.get('embeddableConfig', {}).get('attributes', {}).get('title') or
            ''
        )

    def _panel_type(self, panel):
        # type: (dict) -> str
        if panel.get('type') == 'search':
            return 'search'
        return panel.get('embeddableConfig', {}).get('savedVis', {}).get('type') or panel.get('type')

    def _resolve_reference_panel(self, dashboard, panel, reference_objects):
        # type: (dict, dict, dict) -> dict
        panel_ref_name = panel.get('panelRefName')
        if not panel_ref_name:
            return panel

        reference = None
        for candidate in dashboard.get('references', []):
            ref_name = candidate.get('name', '')
            if ref_name == panel_ref_name or ref_name.endswith(':' + panel_ref_name):
                reference = candidate
                break

        if reference is None:
            return panel

        saved_object = reference_objects.get(reference['type'], {}).get(reference['id'])
        if saved_object is None:
            return panel

        resolved = json.loads(json.dumps(panel))
        resolved.pop('panelRefName', None)
        if reference['type'] == 'visualization':
            vis_state = json.loads(saved_object['attributes']['visState'])
            resolved.setdefault('embeddableConfig', {})['savedVis'] = {
                'title': vis_state.get('title'),
                'type': vis_state.get('type'),
                'aggs': vis_state.get('aggs', []),
                'params': vis_state.get('params', {}),
            }
        elif reference['type'] == 'search':
            resolved['type'] = 'search'
            resolved.setdefault('embeddableConfig', {})['attributes'] = saved_object['attributes']

        return resolved

    def _collect_query_fields(self, value, fields):
        # type: (object, set) -> None
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('field', '%timefield%', 'sourceField') and isinstance(item, str):
                    fields.add(item)
                elif key in ('term', 'terms', 'match_phrase', 'exists', 'range') and isinstance(item, dict):
                    for field_name, field_value in item.items():
                        if field_name == 'field' and isinstance(field_value, str):
                            fields.add(field_value)
                        elif isinstance(field_name, str):
                            fields.add(field_name)
                        self._collect_query_fields(field_value, fields)
                elif key == 'query' and isinstance(item, str):
                    for match in re.findall(r'"?([A-Za-z_@][A-Za-z0-9_@.-]+)"?\s*:', item):
                        fields.add(match)
                else:
                    self._collect_query_fields(item, fields)
        elif isinstance(value, list):
            for item in value:
                self._collect_query_fields(item, fields)

    def _panel_query_signature(self, panel):
        # type: (dict) -> tuple
        indexes = set()
        fields = set()

        def collect_vega_data(data):
            # type: (object) -> None
            if isinstance(data, dict):
                url = data.get('url')
                if isinstance(url, dict):
                    if isinstance(url.get('index'), str):
                        indexes.add(url['index'])
                    self._collect_query_fields(url, fields)
                for item in data.values():
                    collect_vega_data(item)
            elif isinstance(data, list):
                for item in data:
                    collect_vega_data(item)

        spec = panel.get('embeddableConfig', {}).get('savedVis', {}).get('params', {}).get('spec')
        if spec:
            spec_obj = json.loads(spec)
            collect_vega_data(spec_obj.get('data', []))
            spec_text = json.dumps(spec_obj)
            for match in re.findall(r"'([A-Za-z0-9_@.-]+)'\s*:", spec_text):
                if '.' in match or match.startswith('@'):
                    fields.add(match)

        if panel.get('type') == 'search':
            attributes = panel.get('embeddableConfig', {}).get('attributes', {})
            for column in attributes.get('columns', []):
                fields.add(column)
            for sort_item in attributes.get('sort', []):
                if sort_item:
                    fields.add(sort_item[0])
            search_source = attributes.get('kibanaSavedObjectMeta', {}).get('searchSourceJSON')
            if search_source:
                self._collect_query_fields(json.loads(search_source), fields)

        self._collect_query_fields(panel.get('embeddableConfig', {}).get('attributes', {}).get('state', {}), fields)

        ignored_fields = set(['order', 'size'])
        return sorted(indexes), sorted(fields - ignored_fields)

    def _assert_search_panel_uses_saved_object_reference(self, dashboard, panel, objects_by_type):
        # type: (dict, dict, dict) -> dict
        self.assertEqual('search', panel.get('type'))
        self.assertIn('panelRefName', panel, 'Search panel %s must be embedded by reference' % panel.get('title'))
        self.assertNotIn('attributes', panel.get('embeddableConfig', {}), 'Search panel %s should not carry by-value saved search state' % panel.get('title'))

        panel_ref_name = panel.get('panelRefName')
        search_ref = None
        for ref in dashboard.get('references', []):
            ref_name = ref.get('name', '')
            if ref.get('type') == 'search' and (ref_name == panel_ref_name or ref_name.endswith(':' + panel_ref_name)):
                search_ref = ref
                break
        self.assertIsNotNone(search_ref, 'Search panel %s must reference a package search saved object' % panel.get('title'))
        self.assertIn(search_ref['id'], objects_by_type.get('search', {}))
        return objects_by_type['search'][search_ref['id']]['attributes']

    def test_expected_object_counts(self):
        counts, _ = self._load_objects()
        self.assertEqual(EXPECTED_COUNTS, counts)

    def test_all_saved_object_references_resolve(self):
        _, objects_by_type = self._load_objects()

        for object_type in sorted(objects_by_type):
            objects = objects_by_type[object_type]
            for object_id in sorted(objects):
                obj = objects[object_id]
                for reference in obj.get('references', []):
                    ref_type = reference['type']
                    ref_id = reference['id']
                    self.assertIn(ref_type, objects_by_type, 'Missing reference type %s from %s/%s' % (ref_type, object_type, object_id))
                    self.assertIn(ref_id, objects_by_type[ref_type], 'Missing reference id %s (%s) from %s/%s' % (ref_id, ref_type, object_type, object_id))

    def test_dashboards_do_not_use_legacy_saved_object_dependencies(self):
        _, objects_by_type = self._load_objects()

        for dashboard in objects_by_type.get('dashboard', {}).values():
            disallowed_refs = {'links', 'visualization'}
            for reference in dashboard.get('references', []):
                self.assertNotIn(reference['type'], disallowed_refs, 'Dashboard %s still references %s' % (dashboard['id'], reference['type']))

            panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
            for panel in panels:
                if panel.get('type') == 'visualization':
                    self.assertNotIn('panelRefName', panel, 'Dashboard %s still uses by-reference visualization panel %s' % (dashboard['id'], panel.get('panelIndex')))

    def test_dashboards_have_package_safe_navigation(self):
        _, objects_by_type = self._load_objects()

        total_drilldown_refs = 0
        for dashboard in objects_by_type.get('dashboard', {}).values():
            search_source = json.loads(dashboard['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
            for filt in search_source.get('filter', []):
                self.assertNotEqual(filt.get('query', {}).get('exists', {}).get('field'), '@timestamp', 'Dashboard %s still has a dashboard-level @timestamp exists filter' % dashboard['id'])

            drilldown_refs = [
                ref for ref in dashboard.get('references', [])
                if ref['type'] == 'dashboard' and 'DASHBOARD_TO_DASHBOARD_DRILLDOWN' in ref['name']
            ]
            self.assertGreaterEqual(len(drilldown_refs), 1, 'Dashboard %s is missing package-safe navigation drilldowns' % dashboard['id'])
            total_drilldown_refs += len(drilldown_refs)

            panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
            panel_event_count = 0
            for panel in panels:
                events = panel.get('embeddableConfig', {}).get('enhancements', {}).get('dynamicActions', {}).get('events', [])
                for event in events:
                    if event.get('action', {}).get('factoryId') == 'DASHBOARD_TO_DASHBOARD_DRILLDOWN':
                        panel_event_count += 1
            self.assertGreaterEqual(panel_event_count, 1, 'Dashboard %s has no embedded drilldown events' % dashboard['id'])

        self.assertGreaterEqual(total_drilldown_refs, 20)

    def test_dashboards_have_visible_navigation_panel_in_screenshot_order(self):
        _, objects_by_type = self._load_objects()
        expected_labels = [
            'Inventory',
            'Application Report',
            'Application Detail',
            'Certificate Report',
            'Application Connections Topology',
            'Cost Analysis',
        ]

        for dashboard in objects_by_type.get('dashboard', {}).values():
            panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
            nav_panels = [panel for panel in panels if panel.get('panelIndex') == 'tychon-quantum-command-nav']
            self.assertEqual(1, len(nav_panels), 'Dashboard %s must include one visible nav panel' % dashboard['id'])
            nav_panel = nav_panels[0]
            self.assertEqual(0, nav_panel.get('gridData', {}).get('y'), 'Dashboard %s nav panel must be at the top row' % dashboard['id'])
            self.assertEqual(3, nav_panel.get('gridData', {}).get('h'), 'Dashboard %s nav panel should match reference panel height' % dashboard['id'])
            params = nav_panel.get('embeddableConfig', {}).get('savedVis', {}).get('params', {})
            self.assertEqual(12, params.get('fontSize'), 'Dashboard %s nav panel should match reference markdown font size' % dashboard['id'])
            markdown = params.get('markdown', '')
            self.assertNotIn('TYCHON Quantum Command Navigation', markdown, 'Dashboard %s nav panel should not include an extra heading' % dashboard['id'])
            positions = []
            for label in expected_labels:
                pos = markdown.find(label)
                self.assertNotEqual(-1, pos, 'Dashboard %s nav panel is missing label %s' % (dashboard['id'], label))
                positions.append(pos)
            self.assertEqual(sorted(positions), positions, 'Dashboard %s nav labels are out of order' % dashboard['id'])

    def test_package_dashboards_match_reference_saved_object_queries(self):
        # type: () -> None
        _, package_objects = self._load_objects()
        reference_objects = self._load_reference_objects()

        reference_dashboards = reference_objects.get('dashboard', {})
        package_dashboards_by_reference_id = {}
        for dashboard in package_objects.get('dashboard', {}).values():
            package_dashboards_by_reference_id[self._reference_dashboard_id(dashboard['id'])] = dashboard

        self.assertEqual(set(reference_dashboards), set(package_dashboards_by_reference_id))

        for reference_id in sorted(reference_dashboards):
            reference_dashboard = reference_dashboards[reference_id]
            package_dashboard = package_dashboards_by_reference_id[reference_id]
            reference_panels = {}
            for panel in json.loads(reference_dashboard['attributes'].get('panelsJSON', '[]')):
                reference_panels[panel.get('panelIndex')] = self._resolve_reference_panel(reference_dashboard, panel, reference_objects)
            package_panels = {}
            for panel in json.loads(package_dashboard['attributes'].get('panelsJSON', '[]')):
                package_panels[panel.get('panelIndex')] = self._resolve_reference_panel(package_dashboard, panel, package_objects)

            missing_panel_ids = set(reference_panels) - set(package_panels)
            extra_panel_ids = set(package_panels) - set(reference_panels)
            self.assertEqual(
                ['links'],
                sorted(set(self._panel_type(reference_panels[panel_id]) for panel_id in missing_panel_ids)),
                'Dashboard %s has non-navigation panels missing from the package' % package_dashboard['id'],
            )
            self.assertEqual(
                set(['tychon-quantum-command-nav']),
                extra_panel_ids,
                'Dashboard %s has unexpected package-only panels' % package_dashboard['id'],
            )

            for panel_id in sorted(set(reference_panels) & set(package_panels)):
                reference_panel = reference_panels[panel_id]
                package_panel = package_panels[panel_id]
                self.assertEqual(
                    self._panel_title(reference_panel),
                    self._panel_title(package_panel),
                    'Dashboard %s panel %s title drifted from the reference saved object' % (package_dashboard['id'], panel_id),
                )
                self.assertEqual(
                    self._panel_query_signature(reference_panel),
                    self._panel_query_signature(package_panel),
                    'Dashboard %s panel %s query fields drifted from the reference saved object' % (package_dashboard['id'], panel_id),
                )

    def test_package_dashboards_do_not_contain_mojibake(self):
        # type: () -> None
        _, objects_by_type = self._load_objects()
        blocked_markers = ['\\u00e2', '\\u20ac', u'ā', u'â', u'Ã', u'�']

        for dashboard in objects_by_type.get('dashboard', {}).values():
            dashboard_text = json.dumps(dashboard, ensure_ascii=False)
            for marker in blocked_markers:
                self.assertNotIn(marker, dashboard_text, 'Dashboard %s contains mojibake marker %s' % (dashboard['id'], marker))

    def test_application_connections_topology_panel_matches_standalone_visualization(self):
        # type: () -> None
        _, objects_by_type = self._load_objects()

        dashboard = objects_by_type['dashboard'][TOPOLOGY_DASHBOARD_ID]
        visualization = objects_by_type['visualization'][TOPOLOGY_VISUALIZATION_ID]
        visualization_state = json.loads(visualization['attributes']['visState'])

        panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
        topology_panels = [panel for panel in panels if panel.get('title') == 'PQC Connections Topology']
        self.assertEqual(1, len(topology_panels), 'Topology dashboard must embed exactly one PQC Connections Topology panel')

        topology_panel = topology_panels[0]
        saved_vis = topology_panel.get('embeddableConfig', {}).get('savedVis', {})
        inline_state = {
            'title': saved_vis.get('title'),
            'type': saved_vis.get('type'),
            'aggs': saved_vis.get('data', {}).get('aggs', []),
            'params': saved_vis.get('params', {}),
        }
        self.assertEqual(visualization_state, inline_state, 'Topology dashboard panel must stay in sync with the standalone Vega visualization')

        spec = json.loads(visualization_state['params']['spec'])
        raw_sources = [source for source in spec.get('data', []) if source.get('name') == 'raw']
        self.assertEqual(1, len(raw_sources), 'Topology Vega spec must define exactly one raw source')
        self.assertEqual('tychon-pqc-applications', raw_sources[0].get('url', {}).get('index'))
        raw_must = raw_sources[0].get('url', {}).get('body', {}).get('aggs', {}).get('pairs', {}).get('filter', {}).get('bool', {}).get('must', [])
        self.assertIn({'exists': {'field': 'host.hostname'}}, raw_must)
        self.assertIn({'exists': {'field': 'tychon.application.name'}}, raw_must)
        self.assertIn({'term': {'event.dataset': 'tychon.application'}}, raw_must)

    def test_application_visualizations_do_not_filter_on_unreachable_event_dataset(self):
        # type: () -> None
        _, objects_by_type = self._load_objects()

        application_list = objects_by_type['visualization'][APPLICATION_LIST_VISUALIZATION_ID]
        topology = objects_by_type['visualization'][TOPOLOGY_VISUALIZATION_ID]

        app_list_spec = json.loads(json.loads(application_list['attributes']['visState'])['params']['spec'])
        topology_spec = json.loads(json.loads(topology['attributes']['visState'])['params']['spec'])

        app_sources = [source for source in app_list_spec.get('data', []) if source.get('name') == 'apps']
        self.assertEqual(1, len(app_sources), 'Application list visualization must define one apps source')
        self.assertEqual('tychon-pqc-applications', app_sources[0].get('url', {}).get('index'))
        app_filter = app_sources[0].get('url', {}).get('body', {}).get('aggs', {}).get('app_only', {}).get('filter', {})
        self.assertEqual({'term': {'event.dataset': 'tychon.application'}}, app_filter)

        active_signals = [signal for signal in app_list_spec.get('signals', []) if signal.get('name') == 'activeFilter']
        self.assertEqual(1, len(active_signals), 'Application list visualization must define one activeFilter signal')
        active_update = active_signals[0].get('update', '')
        self.assertIn("'event.dataset': 'tychon.application'", active_update)

        self.assertIn("event.dataset", repr(topology_spec))


    def test_application_report_embeds_dod_omb_report_search_panel(self):
        # type: () -> None
        _, objects_by_type = self._load_objects()

        dashboard = objects_by_type['dashboard'][APPLICATION_REPORT_DASHBOARD_ID]
        panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
        omb_panels = [panel for panel in panels if panel.get('title') == 'DoD OMB Report']
        self.assertEqual(1, len(omb_panels), 'Application Report dashboard must embed exactly one DoD OMB Report panel')

        omb_panel = omb_panels[0]
        attributes = self._assert_search_panel_uses_saved_object_reference(dashboard, omb_panel, objects_by_type)
        self.assertEqual('DoD OMB Report', attributes.get('title'))
        self.assertEqual('OMB Report for the Department of Defense', attributes.get('description'))
        self.assertIn('observer.hostname', attributes.get('columns', []))
        self.assertIn('omb.vulnerability_status', attributes.get('columns', []))

        search_source = json.loads(attributes['kibanaSavedObjectMeta']['searchSourceJSON'])
        self.assertEqual('kibanaSavedObjectMeta.searchSourceJSON.index', search_source.get('indexRefName'))
        filters = search_source.get('filter', [])
        self.assertEqual(1, len(filters))
        self.assertEqual('omb.vulnerability_status', filters[0].get('query', {}).get('exists', {}).get('field'))
        self.assertEqual('kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index', filters[0].get('meta', {}).get('indexRefName'))


    def test_certificate_operations_dashboard_embeds_inventory_detail_search_panel(self):
        # type: () -> None
        _, objects_by_type = self._load_objects()

        dashboard = objects_by_type['dashboard'][CERTIFICATE_OPERATIONS_DASHBOARD_ID]
        panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
        inventory_panels = [panel for panel in panels if panel.get('title') == 'Certificate Inventory Detail']
        self.assertEqual(1, len(inventory_panels), 'Certificate Operations dashboard must embed exactly one Certificate Inventory Detail panel')

        inventory_panel = inventory_panels[0]
        attributes = self._assert_search_panel_uses_saved_object_reference(dashboard, inventory_panel, objects_by_type)
        self.assertEqual('Certificate Inventory Detail', attributes.get('title'))
        self.assertIn('observer.hostname', attributes.get('columns', []))
        self.assertIn('x509.subject.common_name', attributes.get('columns', []))
        self.assertEqual([[u'cert_days_remaining', u'asc']], attributes.get('sort'))

        search_source = json.loads(attributes['kibanaSavedObjectMeta']['searchSourceJSON'])
        self.assertEqual('kibanaSavedObjectMeta.searchSourceJSON.index', search_source.get('indexRefName'))
        self.assertEqual([], search_source.get('filter', []))


    def test_application_list_panel_matches_standalone_visualization(self):
        # type: () -> None
        _, objects_by_type = self._load_objects()

        dashboard = objects_by_type['dashboard'][TOPOLOGY_DASHBOARD_ID]
        visualization = objects_by_type['visualization'][APPLICATION_LIST_VISUALIZATION_ID]
        visualization_state = json.loads(visualization['attributes']['visState'])

        panels = json.loads(dashboard['attributes'].get('panelsJSON', '[]'))
        app_panels = [panel for panel in panels if panel.get('title') == 'QuantumApplicationList']
        self.assertEqual(1, len(app_panels), 'Topology dashboard must embed exactly one QuantumApplicationList panel')

        app_panel = app_panels[0]
        saved_vis = app_panel.get('embeddableConfig', {}).get('savedVis', {})
        inline_state = {
            'title': saved_vis.get('title'),
            'type': saved_vis.get('type'),
            'aggs': saved_vis.get('data', {}).get('aggs', []),
            'params': saved_vis.get('params', {}),
        }
        self.assertEqual(visualization_state, inline_state, 'Topology dashboard app list panel must stay in sync with the standalone Vega visualization')


if __name__ == '__main__':
    unittest.main()
