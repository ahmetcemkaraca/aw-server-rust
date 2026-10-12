# Local permissioned plugin host

Build the host with `--no-default-features --features encryption,plugin-runtime`.
It requires SQLCipher and scoped local sessions. The ordinary release constructor
uses an empty `PluginTrust`, so install, consent, invocation and write approval
remain unavailable until release-owned trust and independent sandbox review are
provisioned. No HTTP or settings API can change the trust registry.

Release integration calls `PluginTrust::from_release_registry` and passes its
result to `build_rocket_with_plugin_trust` alongside the existing Egress trust.
The registry contains exact Ed25519 publisher keys, reviewed signed-package
hashes, revoked publisher IDs/package hashes and the SHA-256 digest of the
independent sandbox review artifact. The release integrator must authenticate
that registry and retain the actual review/provenance evidence; merely possessing
a correctly formatted digest is not evidence. Keys must be 32 bytes and hashes
must be lowercase SHA-256. No real registry or review artifact is bundled here.
The runner only activates on compiled desktop x86_64/aarch64 targets; device
acceptance remains a separate release gate.

A package hash is SHA-256 of `serde_json::to_vec(serde_json::to_value(package))`:
recursive sorted JSON object keys, no insignificant whitespace, including the
manifest, module hash and publisher signature. It differs from `module_sha256`.
Every mutating request identifies the exact installed package hash. Verification
rechecks signatures, module bytes, publisher revocations and exact package review
before install, consent, invocation and write approval.

## Routes under `/api/0/plugins`

- `GET /status` reports compiled/runtime/lifecycle/marketplace availability.
- `GET /installed` returns `{schema_version:1,plugins:[...]}`.
- `POST /install` accepts `{package,module_bytes}`. Packages install disabled.
- `POST /<id>/update` also requires `expected_package_sha256`; it returns
  `{plugin,capability_diff}` and always disables the updated package.
- `POST /<id>/consent` accepts `{package_sha256,confirmed:true}`.
- `POST /<id>/invoke` accepts `{package_sha256}` and returns UI text, annotation
  writes, complete Egress previews, AI drafts, an invocation ID and expiry.
- `POST /<id>/writes/approve` accepts
  `{package_sha256,invocation_id,confirmed:true}`. The host retrieves the exact
  prepared annotations; clients cannot substitute write payloads. Approval is
  one-time, expires after five minutes and commits atomically with the writes.
- `POST /<id>/revoke` and `DELETE /<id>` require
  `{package_sha256,confirmed:true}`. Revocation is terminal for that exact package,
  including after uninstall/reinstall. A different reviewed update can be used.
- `GET /<id>/history` returns the last 100 content-free access records.

All lifecycle routes require an Admin scoped local session. Installed state,
module bytes, pending write payloads, plugin storage/events and access history
are stored in SQLCipher (schema v13). Pending nonempty write previews are capped
at 32; no-write invocations do not consume those slots. Installation is capped
at 32 packages and modules at 16 MiB. Only install/update accept up to 65 MiB
of JSON to accommodate byte-array expansion; other local HTTP limits remain unchanged.
Storage mutations and pending-write preparation share one transaction. Preparing
annotations never creates activity events. Uninstall atomically erases the
package, its storage, annotations, pending approvals and history; it preserves
unrelated activity and content-free local revocation tombstones.

Network intents create existing Privacy Firewall previews, never a second
transport. The user reviews and approves/sends through the existing Egress
routes. Update/revoke/delete serialize with in-flight sends, invalidate all
pending outbound previews/approvals, and erase plugin write approvals. This
conservative invalidation can require another review for unrelated outbound
requests. Prepared AI requests are drafts for a new explicit user AI request;
they require the existing AI preview, one-time approval and native credential
confirmation. They are not plugin-owned send tokens or automatic requests.

The current lifecycle increment does not implement background scheduling or
generic destructive export/delete/send resource handling. Such destructive
intents fail invocation rather than touching the vault. These are remaining
implementation work, alongside marketplace product services and external
review/signing/revocation/billing/support operation provisioning; they are not
claims of complete EPIC-12 delivery.
