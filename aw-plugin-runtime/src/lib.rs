//! Core-Wasm plugin execution without WASI or ambient host imports.
use aw_models::SignedPluginPackageV1;
use aw_models::{
    validate_plugin_output_v1, PluginContractErrorV1, PluginInvocationOutputV1, PluginManifestV1,
    ValidatedPluginInputV1, ValidatedPluginOutputV1,
};
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::collections::{BTreeSet, HashMap, HashSet};
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const PLUGIN_PACKAGE_SIGNING_DOMAIN_V1: &[u8] = b"PeakActivity:PluginPackageV1\0";
pub const PLUGIN_MAX_MODULE_BYTES_V1: usize = 16 * 1024 * 1024;
pub const PLUGIN_RUNTIME_MAX_MODULE_BYTES_V1: usize = 16 * 1024 * 1024;
pub const PLUGIN_RUNTIME_MAX_INPUT_BYTES_V1: usize = 1024 * 1024;
pub const PLUGIN_RUNTIME_MAX_OUTPUT_BYTES_V1: usize = 1024 * 1024;
pub const PLUGIN_RUNTIME_MAX_MEMORY_BYTES_V1: usize = 16 * 1024 * 1024;
pub const PLUGIN_RUNTIME_FUEL_V1: u64 = 5_000_000;

const ABI_EXPORTS: [&str; 3] = ["alloc", "invoke", "memory"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginPackageVerificationErrorV1 {
    InvalidPackage,
    UnknownPublisher,
    RevokedPublisher,
    RevokedPackage,
    InvalidSignature,
}

/// Opaque package token created only after publisher signature and module hash verify.
pub struct VerifiedPluginPackageV1 {
    manifest: aw_models::PluginManifestV1,
    module: Vec<u8>,
    module_sha256: String,
}

impl VerifiedPluginPackageV1 {
    pub fn manifest(&self) -> &aw_models::PluginManifestV1 { &self.manifest }
    pub fn module_bytes(&self) -> &[u8] { &self.module }
    pub fn module_sha256(&self) -> &str { &self.module_sha256 }
}

pub fn plugin_package_signing_bytes_v1(
    package: &SignedPluginPackageV1,
) -> Result<Vec<u8>, PluginPackageVerificationErrorV1> {
    package.validate().map_err(|_| PluginPackageVerificationErrorV1::InvalidPackage)?;
    let manifest = serde_json::to_value(&package.manifest)
        .map_err(|_| PluginPackageVerificationErrorV1::InvalidPackage)?;
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|_| PluginPackageVerificationErrorV1::InvalidPackage)?;
    let digest = decode_lower_hex_sha256(&package.module_sha256)?;
    let length = u32::try_from(bytes.len()).map_err(|_| PluginPackageVerificationErrorV1::InvalidPackage)?;
    let mut signed = Vec::with_capacity(PLUGIN_PACKAGE_SIGNING_DOMAIN_V1.len() + 2 + 4 + bytes.len() + 32);
    signed.extend_from_slice(PLUGIN_PACKAGE_SIGNING_DOMAIN_V1);
    signed.extend_from_slice(&package.schema_version.to_be_bytes());
    signed.extend_from_slice(&length.to_be_bytes());
    signed.extend_from_slice(&bytes);
    signed.extend_from_slice(&digest);
    Ok(signed)
}

pub fn verify_plugin_package_v1(
    package: &SignedPluginPackageV1,
    module: &[u8],
    trusted_publishers: &HashMap<String, Vec<u8>>,
    revoked_publishers: &HashSet<String>,
    revoked_package_sha256: &HashSet<String>,
) -> Result<VerifiedPluginPackageV1, PluginPackageVerificationErrorV1> {
    package.validate().map_err(|_| PluginPackageVerificationErrorV1::InvalidPackage)?;
    if module.is_empty() || module.len() > PLUGIN_MAX_MODULE_BYTES_V1 {
        return Err(PluginPackageVerificationErrorV1::InvalidPackage);
    }
    if revoked_publishers.contains(&package.manifest.publisher_key_id) {
        return Err(PluginPackageVerificationErrorV1::RevokedPublisher);
    }
    if revoked_package_sha256.contains(&package.module_sha256) {
        return Err(PluginPackageVerificationErrorV1::RevokedPackage);
    }
    if to_lower_hex(digest(&SHA256, module).as_ref()) != package.module_sha256 {
        return Err(PluginPackageVerificationErrorV1::InvalidPackage);
    }
    let public = trusted_publishers.get(&package.manifest.publisher_key_id)
        .ok_or(PluginPackageVerificationErrorV1::UnknownPublisher)?;
    if public.len() != 32 { return Err(PluginPackageVerificationErrorV1::UnknownPublisher); }
    let signed = plugin_package_signing_bytes_v1(package)?;
    UnparsedPublicKey::new(&ED25519, public)
        .verify(&signed, &package.signature)
        .map_err(|_| PluginPackageVerificationErrorV1::InvalidSignature)?;
    Ok(VerifiedPluginPackageV1 {
        manifest: package.manifest.clone(),
        module: module.to_vec(),
        module_sha256: package.module_sha256.clone(),
    })
}

fn decode_lower_hex_sha256(value: &str) -> Result<[u8; 32], PluginPackageVerificationErrorV1> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(PluginPackageVerificationErrorV1::InvalidPackage);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or(PluginPackageVerificationErrorV1::InvalidPackage)?;
        let low = (pair[1] as char).to_digit(16).ok_or(PluginPackageVerificationErrorV1::InvalidPackage)?;
        output[index] = ((high << 4) | low) as u8;
    }
    Ok(output)
}

fn to_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginRuntimeErrorV1 {
    ModuleTooLarge,
    InputTooLarge,
    InvalidInput,
    InvalidModule,
    ImportsDenied,
    ExportsDenied,
    ExecutionLimit,
    MemoryDenied,
    InvalidOutput,
    CapabilityDenied,
}

struct StoreState {
    limits: StoreLimits,
}

/// Verified modules execute as bounded JSON transformations; each call gets a fresh Store.
pub struct PluginRuntimeV1 {
    engine: Engine,
}

pub struct CompiledPluginV1 {
    module: Module,
    manifest: PluginManifestV1,
    plugin_id: String,
    package_sha256: String,
}

impl PluginRuntimeV1 {
    pub fn new() -> Result<Self, PluginRuntimeErrorV1> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // The Wasmtime dependency omits its `threads` feature entirely.
        let engine = Engine::new(&config).map_err(|_| PluginRuntimeErrorV1::InvalidModule)?;
        Ok(Self { engine })
    }

    pub fn compile_verified(
        &self,
        package: &VerifiedPluginPackageV1,
    ) -> Result<CompiledPluginV1, PluginRuntimeErrorV1> {
        let bytes = package.module_bytes();
        if bytes.is_empty() || bytes.len() > PLUGIN_RUNTIME_MAX_MODULE_BYTES_V1 {
            return Err(PluginRuntimeErrorV1::ModuleTooLarge);
        }
        if bytes.get(..8) != Some(&b"\0asm\x01\0\0\0"[..]) {
            return Err(PluginRuntimeErrorV1::InvalidModule);
        }
        let module = Module::new(&self.engine, bytes).map_err(|_| PluginRuntimeErrorV1::InvalidModule)?;
        if module.imports().next().is_some() {
            return Err(PluginRuntimeErrorV1::ImportsDenied);
        }
        let exports = module.exports().map(|export| export.name().to_owned()).collect::<BTreeSet<_>>();
        if exports.len() != ABI_EXPORTS.len() || ABI_EXPORTS.iter().any(|name| !exports.contains(*name)) {
            return Err(PluginRuntimeErrorV1::ExportsDenied);
        }
        Ok(CompiledPluginV1 {
            module,
            manifest: package.manifest().clone(),
            plugin_id: package.manifest().plugin_id.clone(),
            package_sha256: package.module_sha256().to_owned(),
        })
    }

    pub fn invoke(
        &self,
        plugin: &CompiledPluginV1,
        input: &ValidatedPluginInputV1,
        active_ai_profile_id: Option<&str>,
    ) -> Result<ValidatedPluginOutputV1, PluginRuntimeErrorV1> {
        if !input.is_for_manifest(&plugin.manifest) {
            return Err(PluginRuntimeErrorV1::CapabilityDenied);
        }
        let input = input.serialized();
        if input.len() > PLUGIN_RUNTIME_MAX_INPUT_BYTES_V1 {
            return Err(PluginRuntimeErrorV1::InputTooLarge);
        }
        if !serde_json::from_slice::<serde_json::Value>(input).is_ok_and(|value| value.is_object()) {
            return Err(PluginRuntimeErrorV1::InvalidInput);
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(PLUGIN_RUNTIME_MAX_MEMORY_BYTES_V1)
            .table_elements(1024)
            .instances(1)
            .tables(1)
            .memories(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&self.engine, StoreState { limits });
        store.limiter(|state| &mut state.limits);
        store.set_fuel(PLUGIN_RUNTIME_FUEL_V1).map_err(|_| PluginRuntimeErrorV1::ExecutionLimit)?;
        let instance = Instance::new(&mut store, &plugin.module, &[])
            .map_err(|_| PluginRuntimeErrorV1::InvalidModule)?;
        let memory = instance.get_memory(&mut store, "memory").ok_or(PluginRuntimeErrorV1::ExportsDenied)?;
        let alloc = instance.get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| PluginRuntimeErrorV1::ExportsDenied)?;
        let invoke = instance.get_typed_func::<(i32, i32), i64>(&mut store, "invoke")
            .map_err(|_| PluginRuntimeErrorV1::ExportsDenied)?;
        let input_len = i32::try_from(input.len()).map_err(|_| PluginRuntimeErrorV1::InputTooLarge)?;
        let input_ptr = alloc.call(&mut store, input_len)
            .map_err(|_| PluginRuntimeErrorV1::ExecutionLimit)?;
        if input_ptr < 0 { return Err(PluginRuntimeErrorV1::MemoryDenied); }
        memory.write(&mut store, input_ptr as usize, input)
            .map_err(|_| PluginRuntimeErrorV1::MemoryDenied)?;
        // ABI: invoke(input_ptr, input_len) returns (output_len << 32) | output_ptr.
        let packed = invoke.call(&mut store, (input_ptr, input_len))
            .map_err(|_| PluginRuntimeErrorV1::ExecutionLimit)? as u64;
        let output_ptr = (packed & 0xffff_ffff) as usize;
        let output_len = (packed >> 32) as usize;
        if output_len == 0 || output_len > PLUGIN_RUNTIME_MAX_OUTPUT_BYTES_V1 {
            return Err(PluginRuntimeErrorV1::InvalidOutput);
        }
        let mut output = vec![0; output_len];
        memory.read(&store, output_ptr, &mut output)
            .map_err(|_| PluginRuntimeErrorV1::InvalidOutput)?;
        let output = serde_json::from_slice::<PluginInvocationOutputV1>(&output)
            .map_err(|_| PluginRuntimeErrorV1::InvalidOutput)?;
        validate_plugin_output_v1(&plugin.manifest, output, active_ai_profile_id)
            .map_err(|error| match error {
                PluginContractErrorV1::InvalidOutput => PluginRuntimeErrorV1::InvalidOutput,
                _ => PluginRuntimeErrorV1::CapabilityDenied,
            })
    }
}

impl CompiledPluginV1 {
    pub fn plugin_id(&self) -> &str { &self.plugin_id }
    pub fn package_sha256(&self) -> &str { &self.package_sha256 }
    pub fn manifest(&self) -> &PluginManifestV1 { &self.manifest }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_models::{PluginCapabilitiesV1, PluginInvocationInputV1, PluginManifestV1, SignedPluginPackageV1, validate_plugin_input_v1};
    use chrono::Utc;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::{HashMap, HashSet};

    fn signed_module(wat_source: &str) -> (SignedPluginPackageV1, Vec<u8>, HashMap<String, Vec<u8>>) {
        let module = wat::parse_str(wat_source).unwrap();
        let signer = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let mut package = SignedPluginPackageV1 {
            schema_version: 1,
            manifest: PluginManifestV1 {
                schema_version: 1, plugin_id: "sample-plugin".into(), version: "1.0.0".into(),
                publisher_key_id: "publisher-01".into(), display_name: "Sample".into(),
                description: "Synthetic".into(), capabilities: PluginCapabilitiesV1::default(),
            },
            module_sha256: to_lower_hex(digest(&SHA256, &module).as_ref()),
            signature: vec![0; 64],
        };
        package.signature = signer.sign(&plugin_package_signing_bytes_v1(&package).unwrap()).as_ref().to_vec();
        let mut keys = HashMap::new();
        keys.insert("publisher-01".into(), signer.public_key().as_ref().to_vec());
        (package, module, keys)
    }

    fn verified_module(wat_source: &str) -> VerifiedPluginPackageV1 {
        let (package, module, keys) = signed_module(wat_source);
        verify_plugin_package_v1(&package, &module, &keys, &HashSet::new(), &HashSet::new()).unwrap()
    }

    fn empty_input(manifest: &PluginManifestV1) -> ValidatedPluginInputV1 {
        validate_plugin_input_v1(manifest, PluginInvocationInputV1 { schema_version: 1, records: Vec::new(), storage: Default::default() }, Utc::now()).unwrap()
    }

    fn valid_module(output: &str) -> String {
        let packed = (output.len() as u64) << 32;
        let output = output.bytes().map(|byte| format!("\\{byte:02x}")).collect::<String>();
        format!(r#"(module
            (memory (export "memory") 1 4)
            (func (export "alloc") (param i32) (result i32) i32.const 1024)
            (func (export "invoke") (param i32 i32) (result i64) i64.const {packed})
            (data (i32.const 0) "{output}")
        )"#)
    }

    #[test]
    fn verified_wasm_runs_in_a_fresh_bounded_store_and_returns_json() {
        let runtime = PluginRuntimeV1::new().unwrap();
        let output = r#"{"schema_version":1,"ui":[],"writes":[],"network":[],"ai":[],"storage":[],"destructive":[]}"#;
        let package = verified_module(&valid_module(output));
        let compiled = runtime.compile_verified(&package).unwrap();
        assert_eq!(compiled.plugin_id(), "sample-plugin");
        let input = empty_input(package.manifest());
        assert_eq!(runtime.invoke(&compiled, &input, None).unwrap().as_inner().schema_version, 1);
    }

    #[test]
    fn checked_in_noop_sample_uses_the_v1_core_module_abi() {
        let runtime = PluginRuntimeV1::new().unwrap();
        let package = verified_module(include_str!("../examples/noop-plugin.wat"));
        let compiled = runtime.compile_verified(&package).unwrap();
        let output = runtime.invoke(&compiled, &empty_input(compiled.manifest()), None).unwrap();
        assert_eq!(output.as_inner().schema_version, 1);
        assert!(output.as_inner().network.is_empty());
    }

    #[test]
    fn wasm_imports_and_infinite_loops_are_rejected_or_fuel_limited() {
        let runtime = PluginRuntimeV1::new().unwrap();
        let imported = verified_module(r#"(module (import "wasi_snapshot_preview1" "fd_write" (func)))"#);
        assert_eq!(runtime.compile_verified(&imported).err().unwrap(), PluginRuntimeErrorV1::ImportsDenied);

        let looping = verified_module(r#"(module
            (memory (export "memory") 1 4)
            (func (export "alloc") (param i32) (result i32)
                (loop $forever (br $forever)) unreachable i32.const 0)
            (func (export "invoke") (param i32 i32) (result i64) i64.const 0)
        )"#);
        let compiled = runtime.compile_verified(&looping).unwrap();
        let input = empty_input(compiled.manifest());
        assert_eq!(runtime.invoke(&compiled, &input, None), Err(PluginRuntimeErrorV1::ExecutionLimit));
    }

    #[test]
    fn wasm_memory_growth_and_output_are_bounded() {
        let runtime = PluginRuntimeV1::new().unwrap();
        let growing = verified_module(r#"(module
            (memory (export "memory") 1 512)
            (func (export "alloc") (param i32) (result i32) i32.const 1024)
            (func (export "invoke") (param i32 i32) (result i64) i32.const 300 memory.grow drop i64.const 0)
        )"#);
        let compiled = runtime.compile_verified(&growing).unwrap();
        let input = empty_input(compiled.manifest());
        assert_eq!(runtime.invoke(&compiled, &input, None), Err(PluginRuntimeErrorV1::ExecutionLimit));

        let oversized = (u64::try_from(PLUGIN_RUNTIME_MAX_OUTPUT_BYTES_V1 + 1).unwrap()) << 32;
        let output_module = verified_module(&format!(r#"(module
            (memory (export "memory") 1 4)
            (func (export "alloc") (param i32) (result i32) i32.const 1024)
            (func (export "invoke") (param i32 i32) (result i64) i64.const {oversized})
        )"#));
        let compiled = runtime.compile_verified(&output_module).unwrap();
        let input = empty_input(compiled.manifest());
        assert_eq!(runtime.invoke(&compiled, &input, None), Err(PluginRuntimeErrorV1::InvalidOutput));
    }

    #[test]
    fn runtime_rejects_ungranted_plugin_effects_after_execution() {
        let runtime = PluginRuntimeV1::new().unwrap();
        let output = r#"{"schema_version":1,"ui":[],"writes":[],"network":[{"domain":"api.example.net","destination_id":"vendor-api","purpose_id":"plugin.export","payload_class":"aggregate","payload":{"aggregate":{}}}],"ai":[],"storage":[],"destructive":[]}"#;
        let package = verified_module(&valid_module(output));
        let compiled = runtime.compile_verified(&package).unwrap();
        let input = empty_input(compiled.manifest());
        assert_eq!(runtime.invoke(&compiled, &input, None), Err(PluginRuntimeErrorV1::CapabilityDenied));
    }

    #[test]
    fn validated_input_is_bound_to_its_manifest() {
        let runtime = PluginRuntimeV1::new().unwrap();
        let output = r#"{"schema_version":1,"ui":[],"writes":[],"network":[],"ai":[],"storage":[],"destructive":[]}"#;
        let package = verified_module(&valid_module(output));
        let compiled = runtime.compile_verified(&package).unwrap();
        let mut other_plugin = compiled.manifest().clone();
        other_plugin.plugin_id = "other-plugin".into();
        let mut other_version = compiled.manifest().clone();
        other_version.version = "1.0.1".into();
        let mut other_publisher = compiled.manifest().clone();
        other_publisher.publisher_key_id = "publisher-02".into();
        for manifest in [&other_plugin, &other_version, &other_publisher] {
            let input = empty_input(manifest);
            assert_eq!(runtime.invoke(&compiled, &input, None), Err(PluginRuntimeErrorV1::CapabilityDenied));
        }
    }

    #[test]
    fn package_verification_rejects_changed_bytes_unknown_signers_and_revocations() {
        let (package, module, keys) = signed_module(&valid_module(r#"{"ok":true}"#));
        assert!(verify_plugin_package_v1(&package, &module, &keys, &HashSet::new(), &HashSet::new()).is_ok());
        assert_eq!(verify_plugin_package_v1(&package, &module, &HashMap::new(), &HashSet::new(), &HashSet::new()).err().unwrap(), PluginPackageVerificationErrorV1::UnknownPublisher);
        assert_eq!(verify_plugin_package_v1(&package, b"changed bytes", &keys, &HashSet::new(), &HashSet::new()).err().unwrap(), PluginPackageVerificationErrorV1::InvalidPackage);
        assert_eq!(verify_plugin_package_v1(&package, &module, &keys, &HashSet::from(["publisher-01".into()]), &HashSet::new()).err().unwrap(), PluginPackageVerificationErrorV1::RevokedPublisher);
        assert_eq!(verify_plugin_package_v1(&package, &module, &keys, &HashSet::new(), &HashSet::from([package.module_sha256.clone()])).err().unwrap(), PluginPackageVerificationErrorV1::RevokedPackage);
        let mut altered = package;
        altered.manifest.display_name.push('!');
        assert_eq!(verify_plugin_package_v1(&altered, &module, &keys, &HashSet::new(), &HashSet::new()).err().unwrap(), PluginPackageVerificationErrorV1::InvalidSignature);
    }
}
