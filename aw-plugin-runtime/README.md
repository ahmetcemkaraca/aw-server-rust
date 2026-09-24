# Plugin core-module ABI V1

Modules are core WebAssembly with no imports (WASI is not linked). Export exactly
`memory`, `alloc(i32) -> i32`, and `invoke(i32, i32) -> i64`. The host writes a
bounded JSON input at the pointer returned by `alloc`; `invoke` returns
`(output_length << 32) | output_pointer`. Output must be a strict
`PluginInvocationOutputV1` JSON object and is checked against the verified
manifest before the host prepares effects.

V1 writes are limited to `plugin.annotation` / `annotation-v1` (`title` and
`body`). The host returns them as pending approval inputs; approved annotations
are stored in the encrypted plugin namespace, never in activity events.

[`examples/noop-plugin.wat`](examples/noop-plugin.wat) is a no-effect module for
the Rust tests. It is not a publisher package or an installable app extension.
Execution remains unavailable until publisher trust, host approval routing,
independent sandbox review and supported-target acceptance are provisioned.
