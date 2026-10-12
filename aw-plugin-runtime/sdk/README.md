# Plugin SDK and offline simulator V1

This developer SDK targets the closed [V1 schema](../../schemas/plugin-v1.json),
[core-module ABI](../README.md), and local `/api/0/plugins` host API. It adds no
plugin filesystem, network, credential, raw-vault or process access. The Python
client runs in trusted host tooling, **never inside a plugin**. It requires Python
3.9+ and only the standard library.

Release installation and execution remain unavailable until release-owned
publisher keys, package review/provenance and independent sandbox review are
provided. Marketplace, billing and publisher onboarding are not implemented by
this SDK. A successful simulation is not a security review or release approval.

## Author a module

Use a core WebAssembly target without WASI. Export `memory`, `alloc(i32)->i32`,
and `invoke(i32,i32)->i64`, with no other exports or imports. Input is bounded
JSON with host-filtered `records` and the plugin's own encrypted `storage`.
Return `(output_length << 32) | output_pointer` pointing at UTF-8 JSON.

Return all fields of `PluginInvocationOutputV1`: `schema_version`, `ui`, `writes`,
`network`, `ai`, `storage`, `destructive`. Empty lists mean no action. The
[no-effect sample](../examples/noop-plugin.wat) is the smallest runnable ABI
example; it does not read or modify anything and is not an installable package.

The runtime validates output against the exact signed manifest, with no ambient
imports, fuel and memory limits, and fresh state for each invocation. Raw records
are bounded by bucket/type/time and exact field grants. Aggregate records contain
only granted `event_count` / `total_duration_seconds` with `time_window_days`.
Annotation writes use `plugin.annotation` / `annotation-v1` with only `title`
(maximum 80 characters) and `body` (maximum 4096 characters). Consult the schema
and Rust validator for authoritative limits; the SDK does not reimplement them.

## Offline simulation

Supply four synthetic fixtures:

1. `package.json`: a `SignedPluginPackageV1` signed by your test key.
2. `module.wasm`: the exact core module bytes bound by its SHA-256.
3. `input.json`: `{"schema_version":1,"records":[],"storage":{}}` or synthetic
   records with RFC3339 `captured_at` values within the granted time window.
4. `public-key.json`: the test Ed25519 public key as a JSON array of 32 bytes.

Sign using the runtime's `plugin_package_signing_bytes_v1`; it defines canonical
manifest serialization and domain separation. Do not sign JSON formatted by an
unrelated serializer or mistake the schema-only test vectors for signed packages.
The simulator's unit test demonstrates signing a synthetic no-effect sample.

From this directory:

```sh
python3 peakactivity_plugins.py --synthetic-only package.json module.wasm input.json public-key.json
```

The wrapper invokes `cargo run --offline -p aw-plugin-runtime --example simulate`
from the workspace. The pinned Rust toolchain and dependencies must already be
available; there is no automatic download. The Rust executable accepts the same
four paths after `--synthetic-only` if it is built separately.

The simulator uses the **real** signature verifier, input filter, Wasm compiler,
fuel/memory limits and output capability validator. It prints filtered synthetic
input and validated intents. It applies no storage, annotation, destructive or
network effects, does not contact Egress, and has no active AI profile. Therefore
AI intents are rejected, and network intents do not prove signed host-policy
binding. Revocation registries, package provenance, host aggregate construction,
active AI connection and encrypted lifecycle integration require host tests.
Never give real activity or secrets to this diagnostic output.

## Host lifecycle client

Import `PluginClient` from `peakactivity_plugins.py`. Construct it with a session
token obtained by the authorized native host and a literal loopback HTTP origin,
for example `http://127.0.0.1:5600`. Do not put the token in a URL, CLI argument,
package or plugin input. Proxy environment variables and HTTP redirects are
ignored/rejected so the bearer token cannot follow a remote destination.

| Method | Contract |
| --- | --- |
| `status()` | Reports compiled, lifecycle, operational and marketplace gates. |
| `installed()` / `history(id)` | Lists installed metadata or content-free local access records. |
| `pending(id)` | Lists unexpired manual/background action previews, including per-action approval state. |
| `install(package, module_bytes)` | Verifies the signed package on the host; installs disabled. |
| `update(id, package, module_bytes, expected_package_sha256)` | Uses optimistic package binding; returns `plugin` and `capability_diff`; leaves execution disabled. |
| `consent(id, package_sha256, confirmed=True)` | Grants displayed permissions for exactly this package after explicit employee review. |
| `revoke(id, package_sha256, confirmed=True)` | Stops this exact package permanently; consent cannot undo revocation. |
| `delete(id, package_sha256, confirmed=True)` | Deletes only installed plugin/module/private storage/annotations, preserving revocation records and activity data. |
| `invoke(id, package_sha256)` | Returns a short-lived invocation/action preview; permitted plugin storage writes may be applied by the host. |
| `approve_writes(id, package_sha256, invocation_id, confirmed=True)` | One-time server-bound annotation approval; never accepts replacement payloads. |
| `approve_action(id, package_sha256, invocation_id, action_index, confirmed=True)` | Confirms an exact host-prepared destructive snapshot or releases a scoped network preview; never replaces its resource or payload. |

Do not automatically turn an update response into consent. Show `added` and
`removed` capabilities and the full current permissions first. Do not retry an
uncertain approval/send automatically; inspect history/receipts and request a
fresh preview. Destructive actions are limited to export/delete of the exact
`plugin_owned_data` snapshot and send of a named `network:N` intent. Export returns
plugin storage/annotations for an explicitly requested unencrypted local JSON
download. Delete cannot touch activity or another plugin. Snapshot hashes detect
changes between preview and approval. A scoped send returns a Privacy Firewall
preview only; it still requires separate approval/send. Other resources are denied.
An enabled and consented background grant allows scheduled local execution at its
minimum interval. The host queues nonempty action previews with expiry and reports
`last_background_run_at`; background execution does not approve pending writes,
destructive actions, network or AI. `writes_approved` and each destructive action's
`approved` flag prevent replay on queue reload. Network actions
require a full Privacy Firewall preview and per-request approval/send; AI actions
must use the existing active-connection preview/approval/native send flow. The
SDK deliberately does not implement another network or AI transport. Prepared AI
requests are drafts for a new explicit host request, not plugin approval tokens.
The current host mode, endpoint and policy are revalidated when the user starts
the separate AI preview. UI lifecycle changes discard the displayed drafts; no
prepared draft authorizes a send by itself.

## Focused verification

```sh
python3 -m unittest discover -s aw-plugin-runtime/sdk -p 'test_*.py'
cargo test --offline -p aw-plugin-runtime --example simulate
```

Run from the Rust workspace. The simulator test executes the real no-effect Wasm
sample and rejects changed module bytes. The client tests verify loopback-only
configuration, no redirects, explicit confirmation, exact package binding and
server-bound write approval requests. Existing runtime/host suites cover imports,
resource limits, permissions, encryption and lifecycle atomicity separately.
