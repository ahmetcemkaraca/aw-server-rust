"""Host-side local plugin API client and offline simulator launcher (stdlib only).

Never distribute the local session token to plugin modules. Release gates remain
server-owned; this client cannot register publisher trust or bypass approval.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PluginClient:
    def __init__(self, session_token, origin='http://127.0.0.1:5600'):
        url = urlsplit(origin)
        if (url.scheme != 'http' or url.hostname not in {'127.0.0.1', '::1'}
                or url.username or url.password or url.path not in {'', '/'}
                or url.query or url.fragment or not url.port):
            raise ValueError('A literal loopback HTTP origin with an explicit port is required')
        if not isinstance(session_token, str) or not re.fullmatch('[a-f0-9]{64}', session_token):
            raise ValueError('A host-authorized local session token is required')
        self._origin = origin.rstrip('/')
        self._token = session_token
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, method, suffix, body=None):
        request = Request(self._origin + '/api/0/plugins' + suffix,
                          data=None if body is None else json.dumps(body).encode(),
                          method=method, headers={'Authorization': 'Bearer ' + self._token,
                                                  'Content-Type': 'application/json'})
        try:
            with self._opener.open(request, timeout=30) as response:
                data = response.read(2 * 1024 * 1024 + 1)
        except HTTPError as error:
            raise RuntimeError(f'Plugin API rejected the request (HTTP {error.code}); check status and release gates') from None
        if len(data) > 2 * 1024 * 1024:
            raise ValueError('Plugin API response exceeds 2 MiB')
        return json.loads(data) if data else None

    @staticmethod
    def _path(plugin_id):
        if not isinstance(plugin_id, str) or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', plugin_id):
            raise ValueError('Invalid plugin identifier')
        return '/' + quote(plugin_id, safe='')

    @staticmethod
    def _confirmation(package_sha256, confirmed):
        if confirmed is not True:
            raise ValueError('An explicit user confirmation is required')
        if not re.fullmatch('[a-f0-9]{64}', package_sha256):
            raise ValueError('An exact package SHA-256 is required')
        return {'package_sha256': package_sha256, 'confirmed': True}

    def status(self):
        return self._request('GET', '/status')

    def installed(self):
        return self._request('GET', '/installed')

    def pending(self, plugin_id):
        return self._request('GET', self._path(plugin_id) + '/pending')

    def history(self, plugin_id):
        return self._request('GET', self._path(plugin_id) + '/history')

    def install(self, package, module):
        return self._request('POST', '/install', self._package(package, module))

    def update(self, plugin_id, package, module, expected_package_sha256):
        body = self._package(package, module)
        body['expected_package_sha256'] = self._confirmation(expected_package_sha256, True)['package_sha256']
        return self._request('POST', self._path(plugin_id) + '/update', body)

    @staticmethod
    def _package(package, module):
        if not isinstance(module, bytes) or not 0 < len(module) <= 16 * 1024 * 1024:
            raise ValueError('Module must be 1 byte to 16 MiB')
        if not isinstance(package, dict) or hashlib.sha256(module).hexdigest() != package.get('module_sha256'):
            raise ValueError('Module digest does not match package')
        return {'package': package, 'module_bytes': list(module)}

    def consent(self, plugin_id, package_sha256, *, confirmed=False):
        return self._request('POST', self._path(plugin_id) + '/consent', self._confirmation(package_sha256, confirmed))

    def revoke(self, plugin_id, package_sha256, *, confirmed=False):
        return self._request('POST', self._path(plugin_id) + '/revoke', self._confirmation(package_sha256, confirmed))

    def delete(self, plugin_id, package_sha256, *, confirmed=False):
        return self._request('DELETE', self._path(plugin_id), self._confirmation(package_sha256, confirmed))

    def invoke(self, plugin_id, package_sha256):
        body = {'package_sha256': self._confirmation(package_sha256, True)['package_sha256']}
        return self._request('POST', self._path(plugin_id) + '/invoke', body)

    def approve_writes(self, plugin_id, package_sha256, invocation_id, *, confirmed=False):
        body = self._confirmation(package_sha256, confirmed)
        body['invocation_id'] = invocation_id
        return self._request('POST', self._path(plugin_id) + '/writes/approve', body)

    def approve_action(self, plugin_id, package_sha256, invocation_id, action_index, *, confirmed=False):
        body = self._confirmation(package_sha256, confirmed)
        if type(action_index) is not int or not 0 <= action_index < 32:
            raise ValueError('An exact action index from the displayed preview is required')
        body.update(invocation_id=invocation_id, action_index=action_index)
        return self._request('POST', self._path(plugin_id) + '/actions/approve', body)


def main():
    parser = argparse.ArgumentParser(description='Offline synthetic plugin simulator; no installation or host effects')
    parser.add_argument('--synthetic-only', action='store_true', required=True,
                        help='Acknowledge that all files contain synthetic data and a test key')
    for name in ('package', 'module', 'input', 'public_key'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    command = ['cargo', 'run', '--offline', '-p', 'aw-plugin-runtime', '--example', 'simulate',
               '--', '--synthetic-only']
    command.extend(str(getattr(args, name).resolve()) for name in ('package', 'module', 'input', 'public_key'))
    raise SystemExit(subprocess.run(command, cwd=root, check=False).returncode)


if __name__ == '__main__':
    main()
