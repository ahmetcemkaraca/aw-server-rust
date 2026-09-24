import json
import unittest
from pathlib import Path
from jsonschema import Draft7Validator


ROOT = Path(__file__).resolve().parents[2]


class PluginBoundaryTest(unittest.TestCase):
    def test_manifest_schema_and_synthetic_vectors_are_strict(self):
        schema = json.loads((ROOT / 'schemas/plugin-v1.json').read_text())
        vector = json.loads((ROOT / 'test-vectors/plugin-package-v1.json').read_text())
        self.assertFalse(schema['definitions']['PluginManifestV1'].get('additionalProperties', True))
        self.assertEqual(schema['definitions']['PluginCapabilitiesV1']['properties']['read']['default'], [])
        self.assertEqual(schema['definitions']['PluginStorageCapabilityV1']['properties']['quota_bytes']['maximum'], 524288)
        self.assertEqual(schema['definitions']['PluginInvocationInputV1']['properties']['storage']['type'], 'object')
        self.assertEqual(schema['definitions']['PluginInvocationInputV1']['properties']['storage']['propertyNames']['maxLength'], 128)
        invocation = {'schema_version': 1, 'records': [{
            'data_class': 'aggregate', 'bucket_type': 'app', 'event_type': 'activity',
            'captured_at': '2026-09-24T12:00:00Z', 'time_window_days': 7,
            'payload': {'event_count': 1},
        }], 'storage': {'theme': 'dark'}}
        Draft7Validator(schema).validate(invocation)
        self.assertFalse(Draft7Validator(schema).is_valid({**invocation, 'ambient': True}))
        aggregate_manifest = dict(vector['valid_package']['manifest'])
        aggregate_manifest['capabilities'] = {**aggregate_manifest['capabilities'], 'read': [{
            'data_class': 'aggregate', 'bucket_type': 'app', 'event_type': 'activity',
            'time_window_days': 7, 'fields': ['/event_count', '/total_duration_seconds'],
        }]}
        Draft7Validator(schema).validate(aggregate_manifest)
        aggregate_manifest['capabilities']['read'][0]['fields'] = ['/title']
        self.assertFalse(Draft7Validator(schema).is_valid(aggregate_manifest))
        self.assertEqual(len(vector['valid_package']['signature']), 64)
        self.assertEqual(len(vector['valid_package']['module_sha256']), 64)

    def test_signature_verifier_checks_bytes_and_has_no_transport(self):
        runtime = (ROOT / 'aw-plugin-runtime/src/lib.rs').read_text()
        egress = (ROOT / 'aw-egress/src/plugin.rs').read_text()
        self.assertIn('verify_plugin_package_v1', runtime)
        self.assertIn('PLUGIN_PACKAGE_SIGNING_DOMAIN_V1', runtime)
        self.assertIn('revoked_package_sha256', runtime)
        self.assertIn('validate_plugin_egress_grants_v1', egress)
        self.assertNotIn('reqwest::', runtime)
        self.assertNotIn('Client::builder', runtime)
        self.assertIn('consume_fuel(true)', runtime)
        self.assertIn('StoreLimitsBuilder', runtime)
        self.assertIn('module.imports().next().is_some()', runtime)
        self.assertIn('validate_plugin_output_v1', runtime)
        self.assertIn('"aw-plugin-runtime"', (ROOT / 'Cargo.toml').read_text())

    def test_plugin_execution_is_hard_gated_without_a_sandbox_runtime(self):
        route = (ROOT / 'aw-server/src/endpoints/plugins.rs').read_text()
        endpoints = (ROOT / 'aw-server/src/endpoints/mod.rs').read_text()
        self.assertIn('runtime_available: false', route)
        self.assertIn('marketplace_available: false', route)
        self.assertIn('routes![plugins::status]', endpoints)
        self.assertNotIn('plugin_host', endpoints)
        self.assertNotIn('PluginRuntime::execute', route)
        webui = ROOT.parent / 'aw-webui'
        view = (webui / 'src/views/settings/PluginSettings.vue').read_text()
        settings = (webui / 'src/views/settings/Settings.vue').read_text()
        route_config = (webui / 'src/route.js').read_text()
        self.assertIn('No plugin module can be installed or executed', view)
        self.assertIn('Plugin approval and install/update/revoke/delete lifecycle integration', view)
        self.assertIn("id: 'plugins'", settings)
        self.assertIn('plugins|developer', route_config)

    def test_plugin_storage_is_sqlcipher_only_and_namespaced_by_publisher(self):
        datastore = (ROOT / 'aw-datastore/src/datastore.rs').read_text()
        worker = (ROOT / 'aw-datastore/src/worker.rs').read_text()
        self.assertIn('CREATE TABLE plugin_storage', datastore)
        self.assertIn('publisher_key_id, plugin_id, storage_key', datastore)
        self.assertIn('GetPluginStorage', worker)
        self.assertIn('ApplyPluginStorageIntents', worker)
        self.assertIn('Self::GetPluginStorage(_)', worker)

    def test_plugin_annotation_write_schema_is_closed_and_bounded(self):
        schema = json.loads((ROOT / 'schemas/plugin-v1.json').read_text())
        validator = Draft7Validator(schema)
        valid = {'schema_version': 1, 'ui': [], 'writes': [{
            'event_type': 'plugin.annotation', 'schema_id': 'annotation-v1',
            'payload': {'title': 'Review', 'body': 'Check totals'},
        }], 'network': [], 'ai': [], 'storage': [], 'destructive': []}
        self.assertTrue(validator.is_valid(valid))
        self.assertFalse(validator.is_valid({**valid, 'writes': [{
            **valid['writes'][0],
            'payload': {'title': 'Review', 'body': 'Check totals', 'path': '/private/file'},
        }]}))
        self.assertFalse(validator.is_valid({**valid, 'writes': [{
            **valid['writes'][0], 'schema_id': 'unknown-v1',
        }]}))
        self.assertFalse(validator.is_valid({**valid, 'writes': [{
            **valid['writes'][0], 'payload': {'title': 'x' * 81, 'body': 'Check totals'},
        }]}))


if __name__ == '__main__':
    unittest.main()
