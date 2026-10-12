//! Offline developer simulator. Caller-provided keys are never release trust.
use aw_models::{validate_plugin_input_v1, PluginInvocationInputV1, SignedPluginPackageV1};
use aw_plugin_runtime::{verify_plugin_package_v1, PluginRuntimeV1};
use chrono::Utc;
use std::{collections::{HashMap, HashSet}, io::Read};

fn bounded_file(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| "Cannot open simulator input")?
        .take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| "Cannot read simulator input")?;
    if bytes.len() > limit { return Err("Simulator input exceeds its limit".into()); }
    Ok(bytes)
}

fn simulate(package: SignedPluginPackageV1, module: Vec<u8>, input: PluginInvocationInputV1, key: Vec<u8>) -> Result<serde_json::Value, String> {
    let keys = HashMap::from([(package.manifest.publisher_key_id.clone(), key)]);
    let verified = verify_plugin_package_v1(&package, &module, &keys, &HashSet::new(), &HashSet::new())
        .map_err(|error| format!("Package rejected: {error:?}"))?;
    let input = validate_plugin_input_v1(verified.manifest(), input, Utc::now())
        .map_err(|error| format!("Input rejected: {error:?}"))?;
    let runtime = PluginRuntimeV1::new().map_err(|error| format!("Runtime unavailable: {error:?}"))?;
    let compiled = runtime.compile_verified(&verified).map_err(|error| format!("Module rejected: {error:?}"))?;
    let output = runtime.invoke(&compiled, &input, None).map_err(|error| format!("Invocation rejected: {error:?}"))?;
    Ok(serde_json::json!({
        "schema_version": 1,
        "simulation_only": true,
        "release_trust_verified": false,
        "host_effects_applied": false,
        "filtered_input": serde_json::from_slice::<serde_json::Value>(input.serialized()).map_err(|_| "Invalid filtered input")?,
        "validated_intents": output.into_inner(),
    }))
}

fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 5 || args[0] != "--synthetic-only" {
        return Err("Usage: simulate --synthetic-only package.json module.wasm input.json public-key.json\nOnly use synthetic data and a test publisher key. This does not install or approve a plugin.".into());
    }
    let package = serde_json::from_slice(&bounded_file(&args[1], 1024 * 1024)?).map_err(|_| "Invalid package JSON")?;
    let module = bounded_file(&args[2], 16 * 1024 * 1024)?;
    let input = serde_json::from_slice(&bounded_file(&args[3], 1024 * 1024)?).map_err(|_| "Invalid input JSON")?;
    let key = serde_json::from_slice(&bounded_file(&args[4], 1024)?).map_err(|_| "Public key must be a JSON byte array")?;
    simulate(package, module, input, key)
}

fn main() {
    match run() {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_models::{PluginCapabilitiesV1, PluginManifestV1};
    use aw_plugin_runtime::plugin_package_signing_bytes_v1;
    use ring::{digest::{digest, SHA256}, signature::{Ed25519KeyPair, KeyPair}};

    #[test]
    fn real_runtime_accepts_noop_and_rejects_changed_module() {
        let module = wat::parse_str(include_str!("noop-plugin.wat")).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let mut package = SignedPluginPackageV1 {
            schema_version: 1,
            manifest: PluginManifestV1 {
                schema_version: 1, plugin_id: "simulator-test".into(), version: "1.0.0".into(),
                publisher_key_id: "synthetic-key".into(), display_name: "Synthetic sample".into(),
                description: "Test only".into(), capabilities: PluginCapabilitiesV1::default(),
            },
            module_sha256: digest(&SHA256, &module).as_ref().iter().map(|byte| format!("{byte:02x}")).collect(),
            signature: vec![0; 64],
        };
        package.signature = key.sign(&plugin_package_signing_bytes_v1(&package).unwrap()).as_ref().to_vec();
        let input = || PluginInvocationInputV1 { schema_version: 1, records: Vec::new(), storage: Default::default() };
        let report = simulate(package.clone(), module.clone(), input(), key.public_key().as_ref().to_vec()).unwrap();
        assert_eq!(report["host_effects_applied"], false);
        assert_eq!(report["validated_intents"]["writes"], serde_json::json!([]));
        let mut changed = module;
        changed.push(0);
        assert!(simulate(package, changed, input(), key.public_key().as_ref().to_vec()).is_err());
    }
}
