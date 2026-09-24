import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ROOT.parent
WEBUI = COMPONENTS / 'aw-webui'


class AiBoundaryTest(unittest.TestCase):
    def test_ai_schema_is_versioned_and_rejects_unknown_modes(self):
        schema_path = ROOT / 'schemas/ai-v1.json'
        self.assertTrue(schema_path.is_file())
        schema = json.loads(schema_path.read_text())
        def get_schema(name):
            for item in schema['oneOf']:
                if item.get('title') == name:
                    return item
                if item.get('$ref') == f"#/definitions/{name}":
                    return schema['definitions'][name]
            self.fail(f'{name} is missing from the AI schema')

        settings = get_schema('AISettingsV1')
        self.assertFalse(settings.get('additionalProperties', True))
        self.assertEqual(settings['properties']['mode']['enum'], ['off', 'peak_ai', 'custom_endpoint'])
        profile = get_schema('AIEndpointProfileV1')
        self.assertEqual(profile['properties']['protocol']['enum'], ['openai_chat_completions_v1'])
        request = get_schema('AIUserRequestV1')
        self.assertEqual(len(request['oneOf']), 5)
        for aggregate in ('AIReportAggregateV1', 'AICategoryAggregateV1', 'AITimesheetAggregateV1'):
            self.assertFalse(schema['definitions'][aggregate].get('additionalProperties', True))

    def test_ai_request_route_uses_egress_and_never_constructs_a_transport(self):
        route_path = ROOT / 'aw-server/src/endpoints/ai.rs'
        self.assertTrue(route_path.is_file())
        route = route_path.read_text()
        self.assertIn('EgressProxy', route)
        self.assertIn('preview', route)
        self.assertIn('approve', route)
        self.assertNotIn('reqwest::Client', route)
        self.assertNotIn('Client::builder', route)

    def test_ai_routes_require_active_mode_and_native_only_send_scope(self):
        route_path = ROOT / 'aw-server/src/endpoints/ai.rs'
        self.assertTrue(route_path.is_file())
        route = route_path.read_text()
        self.assertIn('AISettingsV1::default()', (ROOT / 'aw-datastore/src/worker.rs').read_text())
        self.assertIn('AiSendOnly', route)
        self.assertIn('X-PeakActivity-AI-Credential', route)
        self.assertIn('send_custom_ai_approval', route)
        self.assertIn('config.auth.sessions.is_some()', route)
        self.assertNotIn('Log::', route)

    def test_saved_ai_insights_are_opt_in_bounded_and_deletable(self):
        models = (ROOT / 'aw-models/src/ai.rs').read_text()
        datastore = (ROOT / 'aw-datastore/src/worker.rs').read_text()
        route = (ROOT / 'aw-server/src/endpoints/ai.rs').read_text()
        view = (WEBUI / 'src/components/AIReportExplanation.vue').read_text()
        self.assertIn('AI_MAX_HISTORY_ENTRIES_V1', models)
        self.assertIn('pub fn save_ai_insight', datastore)
        self.assertIn('pub fn delete_ai_insight', datastore)
        self.assertIn('history_save', route)
        self.assertIn('history_delete', route)
        self.assertIn('Save this result', view)
        self.assertIn('Delete saved insight', view)

    def test_custom_endpoint_uses_signed_purpose_and_exact_address_pins(self):
        egress = (ROOT / 'aw-egress/src/lib.rs').read_text()
        endpoint_path = ROOT / 'aw-egress/src/ai.rs'
        self.assertTrue(endpoint_path.is_file())
        endpoint = endpoint_path.read_text()
        self.assertIn('for_custom_endpoint', egress)
        self.assertIn('ai.custom_endpoint', egress)
        self.assertIn('validate_custom_endpoint_addresses', endpoint)
        self.assertIn('resolve_pinned_addresses', endpoint)
        self.assertNotIn('Client::builder', endpoint)
        self.assertNotIn('reqwest::', endpoint)
        proxy = (ROOT / 'aw-egress/src/proxy.rs').read_text()
        self.assertIn('fn test_connection(', proxy)
        self.assertIn('client.head(target)', proxy)
        self.assertIn('redirect(Policy::none())', proxy)
        self.assertIn('.https_only(true)', proxy)
        self.assertFalse('pub fn test_custom_endpoint(' in endpoint, 'the raw connection probe must stay inside EgressProxy')
        self.assertIn('pub fn test_custom_endpoint(', proxy)
        self.assertIn('self.transport.test_connection(profile)', proxy)
        self.assertIn('lease.egress_kill_switch()', proxy)
        self.assertIn('record_egress_receipt', proxy)

    def test_custom_endpoint_keeps_credentials_out_of_serialized_profile(self):
        model_path = ROOT / 'aw-models/src/ai.rs'
        self.assertTrue(model_path.is_file())
        models = model_path.read_text()
        self.assertIn('credential_ref: Option<String>', models)
        self.assertNotIn('credential_value:', models)
        self.assertNotIn('api_key:', models)
        self.assertIn('resolved_addresses: Vec<String>', models)
        self.assertIn('authentication: AIAuthenticationV1', models)

    def test_ai_store_is_encrypted_revisioned_and_hidden_from_generic_settings(self):
        worker_path = ROOT / 'aw-datastore/src/worker.rs'
        datastore_path = ROOT / 'aw-datastore/src/datastore.rs'
        self.assertTrue(worker_path.is_file())
        worker = worker_path.read_text()
        datastore = datastore_path.read_text()
        self.assertIn('Self::GetAISettings()', worker)
        self.assertIn('Self::CompareAndSetAISettings(_, _)', worker)
        self.assertIn('current.revision != expected_revision', worker)
        self.assertIn('AI_SETTINGS_KEY', worker)
        self.assertIn('key == AI_SETTINGS_KEY', datastore)

    def test_ai_settings_default_off_and_ui_never_persists_credentials(self):
        model_path = ROOT / 'aw-models/src/ai.rs'
        self.assertTrue(model_path.is_file())
        models = model_path.read_text()
        self.assertIn('Default for AISettingsV1', models)
        self.assertIn('AIAccessModeV1::Off', models)
        store_path = WEBUI / 'src/stores/ai.ts'
        view_path = WEBUI / 'src/views/settings/AISettings.vue'
        self.assertTrue(store_path.is_file())
        self.assertTrue(view_path.is_file())
        store = store_path.read_text()
        view = view_path.read_text()
        self.assertNotIn('localStorage', store)
        self.assertIn('autocomplete="off"', view)
        self.assertIn('type="password"', view)
        self.assertIn('credential', view.lower())
        self.assertIn('previewFeature', store)
        self.assertIn('approval.feature !== feature', store)
        save_draft = view[view.index('async saveDraft()'):view.index('async testSavedProfile')]
        self.assertLess(save_draft.index('this.credentialInput = \'\''), save_draft.index('this.store.saveCredential(secret)'))

    def test_work_report_ai_input_contains_only_the_displayed_daily_aggregate(self):
        work_report_path = WEBUI / 'src/views/WorkReport.vue'
        panel_path = WEBUI / 'src/components/AIReportExplanation.vue'
        self.assertTrue(panel_path.is_file())
        work_report = work_report_path.read_text()
        panel = panel_path.read_text()
        self.assertIn('AIReportExplanation(v-if="aiAggregate" id-prefix="work-report-ai" :aggregate="aiAggregate" :features="aiFeatures")', work_report)
        self.assertIn('daily: this.dailyData.slice(0, 62).map', work_report)
        self.assertIn("'report_explanation'", panel)
        self.assertIn("'question_answer'", panel)
        self.assertIn(":features=\"['category_suggestion']\"", work_report)
        self.assertIn(":features=\"['freelancer_draft']\"", work_report)
        self.assertIn('aiTimesheetAggregate(): Record<string, unknown>', work_report)
        self.assertNotIn('rawData', panel)
        self.assertNotIn('fieldSummaries.app', work_report[work_report.index('aiAggregate():'):work_report.index('focusDuration()')])

    def test_custom_ai_filters_structured_aggregate_before_building_wire_payload(self):
        proxy = (ROOT / 'aw-egress/src/proxy.rs').read_text()
        route = (ROOT / 'aw-server/src/endpoints/ai.rs').read_text()
        self.assertIn('pub fn preview_custom_ai(', proxy)
        self.assertIn('policy_payload', proxy)
        self.assertIn('policy_snapshot', proxy)
        self.assertIn('render_custom_ai_payload', proxy)
        self.assertIn('preview_custom_ai(', route)
        self.assertNotIn('serde_json::to_string(&request.aggregate)', route)
        self.assertIn('valid_feature_aggregate', (ROOT / 'aw-models/src/ai.rs').read_text())

    def test_ai_preview_and_result_are_invalidated_when_aggregate_changes(self):
        panel = (WEBUI / 'src/components/AIReportExplanation.vue').read_text()
        self.assertRegex(panel, r'watch:\s*\{[\s\S]*?aggregate[\s\S]*?clearPreview')
        store = (WEBUI / 'src/stores/ai.ts').read_text()
        self.assertIn('requestId !== this.previewRequestId', store)
        self.assertIn('discards a preview response after its aggregate was cleared', (WEBUI / 'test/unit/store/ai.test.node.ts').read_text())

    def test_simultaneous_ai_panels_use_unique_accessibility_ids(self):
        work_report = (WEBUI / 'src/views/WorkReport.vue').read_text()
        panel = (WEBUI / 'src/components/AIReportExplanation.vue').read_text()
        self.assertEqual(work_report.count('id-prefix='), 3)
        self.assertIn('idPrefix', panel)
        self.assertIn("idPrefix + '-question'", panel)

    def test_native_approval_id_is_post_body_and_ipv6_reserved_ranges_are_rejected(self):
        route = (ROOT / 'aw-server/src/endpoints/ai.rs').read_text()
        tauri = (COMPONENTS / 'aw-tauri/src-tauri/src/ai_credentials.rs').read_text()
        proxy = (ROOT / 'aw-egress/src/proxy.rs').read_text()
        self.assertIn('#[post("/native-preview/<preview_id>"', route)
        self.assertIn('client.post(format!("http://127.0.0.1:{port}/api/0/ai/native-preview/', tauri)
        self.assertNotIn('?approval_id=', tauri)
        self.assertIn('2001:2::1', proxy)
        self.assertIn('2001:10::1', proxy)
        self.assertIn('ai_approval_expiry', route)
        self.assertIn('Duration::minutes(5)', route)

    def test_tauri_owns_ai_secrets_and_native_send_uses_only_scoped_loopback(self):
        component = ROOT.parent / 'aw-tauri/src-tauri/src/ai_credentials.rs'
        self.assertTrue(component.is_file())
        source = component.read_text()
        local_session = (ROOT.parent / 'aw-tauri/src-tauri/src/local_session.rs').read_text()
        self.assertIn('keyring::Entry', source)
        self.assertIn('Scope::AiSend', local_session)
        self.assertIn('"Authorization"', source)
        self.assertNotIn('TOKEN_HEADER', source)
        self.assertIn('AI_CREDENTIAL_INDEX_ACCOUNT', (COMPONENTS / 'aw-tauri/src-tauri/src/vault.rs').read_text())
        self.assertIn('AI_CREDENTIAL_ACCOUNT_PREFIX', (COMPONENTS / 'aw-tauri/src-tauri/src/vault.rs').read_text())
        self.assertIn('127.0.0.1:{port}/api/0/ai/send', source)
        self.assertIn('X-PeakActivity-AI-Credential', source)
        self.assertNotIn('Log::', source)

    def test_native_ai_send_requires_os_confirmation_of_server_cached_payload(self):
        route = (ROOT / 'aw-server/src/endpoints/ai.rs').read_text()
        tauri = (COMPONENTS / 'aw-tauri/src-tauri/src/ai_credentials.rs').read_text()
        self.assertIn('native_preview', route)
        self.assertIn('Scope::AiSend', (ROOT / 'aw-server/src/sessions.rs').read_text())
        self.assertIn('native-preview/{native_preview_id}', tauri)
        self.assertIn('"approval_id": &request.approval_id', tauri)
        self.assertNotIn('?approval_id=', tauri)
        self.assertIn('blocking_show()', tauri)
        self.assertIn('sanitized_payload', tauri)
        self.assertIn('Cancel', tauri)


if __name__ == '__main__':
    unittest.main()
