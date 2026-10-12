import hashlib
import unittest
from unittest.mock import patch
from peakactivity_plugins import PluginClient, _NoRedirect


class SDKTest(unittest.TestCase):
    def test_local_origin_and_explicit_confirmations(self):
        for origin in ('https://example.com:443', 'http://127.0.0.1:5600@evil.example',
                       'http://localhost:5600', 'http://127.0.0.1:5600/path'):
            with self.assertRaises(ValueError):
                PluginClient('a' * 64, origin)
        client = PluginClient('a' * 64)
        with patch.object(client, '_request') as request:
            for action in (client.consent, client.revoke, client.delete):
                with self.assertRaises(ValueError):
                    action('test-plugin', 'b' * 64)
            request.assert_not_called()
            client.delete('test-plugin', 'b' * 64, confirmed=True)
            request.assert_called_once_with('DELETE', '/test-plugin', {'package_sha256': 'b' * 64, 'confirmed': True})
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, '', {}, 'http://evil.example'))

    def test_update_binds_digest_and_invocation_approval_never_sends_payload(self):
        client = PluginClient('a' * 64)
        module = b'\0asm'
        package = {'module_sha256': hashlib.sha256(module).hexdigest()}
        with patch.object(client, '_request') as request:
            client.update('test-plugin', package, module, 'b' * 64)
            self.assertEqual(request.call_args.args[2]['expected_package_sha256'], 'b' * 64)
            with self.assertRaises(ValueError):
                client.install(package, b'changed')
            client.approve_writes('test-plugin', 'b' * 64, 'invocation', confirmed=True)
            self.assertEqual(request.call_args.args, ('POST', '/test-plugin/writes/approve', {
                'package_sha256': 'b' * 64, 'invocation_id': 'invocation', 'confirmed': True,
            }))

    def test_pending_and_scoped_actions_remain_explicit_and_server_bound(self):
        client = PluginClient('a' * 64)
        with patch.object(client, '_request') as request:
            client.pending('test-plugin')
            request.assert_called_once_with('GET', '/test-plugin/pending')
            request.reset_mock()
            for index in (-1, 32, True):
                with self.assertRaises(ValueError):
                    client.approve_action('test-plugin', 'b' * 64, 'invocation', index, confirmed=True)
            with self.assertRaises(ValueError):
                client.approve_action('test-plugin', 'b' * 64, 'invocation', 0)
            request.assert_not_called()
            client.approve_action('test-plugin', 'b' * 64, 'invocation', 0, confirmed=True)
            request.assert_called_once_with('POST', '/test-plugin/actions/approve', {
                'package_sha256': 'b' * 64, 'invocation_id': 'invocation', 'action_index': 0, 'confirmed': True,
            })


if __name__ == '__main__':
    unittest.main()
