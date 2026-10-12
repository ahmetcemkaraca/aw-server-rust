use aw_datastore::{Datastore, plugins::plugin_package_hash};
use aw_models::{PluginCapabilitiesV1, PluginManifestV1, PluginWriteCapabilityV1, SignedPluginPackageV1};
use aw_server::{config::AWConfig, endpoints::{self, AssetResolver, ServerState, PluginTrust, EgressPolicyTrust}, sessions::{Sessions, Scope}};
use aw_plugin_runtime::plugin_package_signing_bytes_v1;
use ring::{digest::{digest, SHA256}, signature::{Ed25519KeyPair, KeyPair}};
use rocket::{http::{ContentType, Header, Method, Status}, local::blocking::Client};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

fn package(version: &str, writes: bool) -> (SignedPluginPackageV1, Vec<u8>) {
    let output = json!({"schema_version":1,"ui":[],"writes":if writes {vec![json!({"event_type":"plugin.annotation","schema_id":"annotation-v1","payload":{"title":"Review","body":"Synthetic annotation"}})]} else {vec![]},"network":[],"ai":[],"storage":[],"destructive":[]}).to_string();
    let escaped = output.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    let packed = (output.len() as u64) << 32;
    let module = wat::parse_str(format!(r#"(module (memory (export "memory") 1 4)
        (func (export "alloc") (param i32) (result i32) i32.const 4096)
        (func (export "invoke") (param i32 i32) (result i64) i64.const {packed})
        (data (i32.const 0) "{escaped}"))"#)).unwrap();
    let signer = Ed25519KeyPair::from_seed_unchecked(&[117;32]).unwrap();
    let mut package = SignedPluginPackageV1 {
        schema_version:1,
        manifest: PluginManifestV1 {
            schema_version:1, plugin_id:"test-plugin".into(), version:version.into(), publisher_key_id:"test-publisher".into(),
            display_name:"Synthetic test plugin".into(), description:"Not a release package".into(),
            capabilities: PluginCapabilitiesV1 { write: if writes { vec![PluginWriteCapabilityV1 { event_type:"plugin.annotation".into(), schema_id:"annotation-v1".into() }] } else {vec![]}, ..Default::default() },
        },
        module_sha256: digest(&SHA256, &module).as_ref().iter().map(|b|format!("{b:02x}")).collect(), signature:vec![0;64],
    };
    package.signature = signer.sign(&plugin_package_signing_bytes_v1(&package).unwrap()).as_ref().to_vec();
    (package, module)
}
fn setup(packages: &[&SignedPluginPackageV1], release_ready: bool) -> (Client, Datastore, String, String) {
    let store = Datastore::open_encrypted(":memory:".into(), "plugin-route-test-key".repeat(3)).unwrap();
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let read = sessions.mint(Scope::Read).unwrap();
    let mut config = AWConfig::default(); config.port=5600; config.auth.sessions=Some(sessions);
    let trust = if release_ready {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[117;32]).unwrap();
        PluginTrust::from_release_registry(HashMap::from([("test-publisher".into(), signer.public_key().as_ref().to_vec())]),
            packages.iter().map(|p|plugin_package_hash(p).unwrap()).collect(), HashSet::new(), HashSet::new(), "a".repeat(64)).unwrap()
    } else { PluginTrust::default() };
    let state = ServerState { datastore:store.clone(), asset_resolver:AssetResolver::new(None), device_id:"synthetic".into() };
    (Client::tracked(endpoints::build_rocket_with_plugin_trust(state,config,EgressPolicyTrust::default(),trust)).unwrap(), store, admin, read)
}
fn request(client:&Client, token:&str, method:Method, path:&str, body:Value) -> (Status, Value) {
    let mut req=client.req(method, format!("/api/0/plugins{path}"))
        .header(Header::new("Host","localhost:5600")).header(Header::new("Authorization",format!("Bearer {token}")));
    if method != Method::Get {req=req.header(ContentType::JSON).body(body.to_string());}
    let res=req.dispatch(); let status=res.status();
    (status, serde_json::from_str(&res.into_string().unwrap_or_default()).unwrap_or(Value::Null))
}
fn expect(client:&Client, token:&str, method:Method, path:&str, body:Value, status:Status)->Value {
    let (actual,result)=request(client,token,method,path,body); assert_eq!(actual,status,"{path}: {result}"); result
}
#[test]
fn installed_package_flow_requires_scoped_auth_review_consent_and_single_use_write_approval() {
    let (p1,m1)=package("1.0.0",false); let (p2,m2)=package("1.1.0",true);
    let (client,store,admin,read)=setup(&[&p1,&p2],true);
    expect(&client,&read,Method::Get,"/installed",Value::Null,Status::Forbidden);
    expect(&client,"invalid",Method::Get,"/installed",Value::Null,Status::Unauthorized);
    let initial=expect(&client,&admin,Method::Post,"/install",json!({"package":p1,"module_bytes":m1}),Status::Ok);
    store.create_bucket(&aw_models::Bucket { bid:None,id:"unrelated-activity".into(),_type:"app".into(),client:"test".into(),hostname:"test".into(),created:None,data:Default::default(),metadata:Default::default(),events:None,last_updated:None }).unwrap();
    let hash1=initial["package_sha256"].as_str().unwrap(); assert_eq!(initial["enabled"],false);
    expect(&client,&admin,Method::Post,"/test-plugin/invoke",json!({"package_sha256":hash1}),Status::Forbidden);
    expect(&client,&admin,Method::Post,"/test-plugin/consent",json!({"package_sha256":hash1,"confirmed":false}),Status::BadRequest);
    expect(&client,&admin,Method::Post,"/test-plugin/consent",json!({"package_sha256":hash1,"confirmed":true}),Status::Ok);
    expect(&client,&admin,Method::Post,"/test-plugin/invoke",json!({"package_sha256":hash1}),Status::Ok);
    let updated=expect(&client,&admin,Method::Post,"/test-plugin/update",json!({"package":p2,"module_bytes":m2,"expected_package_sha256":hash1}),Status::Ok);
    assert_eq!(updated["plugin"]["enabled"],false); assert_eq!(updated["capability_diff"]["requires_reconsent"],true);
    let hash2=updated["plugin"]["package_sha256"].as_str().unwrap();
    expect(&client,&admin,Method::Post,"/test-plugin/consent",json!({"package_sha256":hash1,"confirmed":true}),Status::Conflict);
    expect(&client,&admin,Method::Post,"/test-plugin/consent",json!({"package_sha256":hash2,"confirmed":true}),Status::Ok);
    let invoked=expect(&client,&admin,Method::Post,"/test-plugin/invoke",json!({"package_sha256":hash2}),Status::Ok);
    assert_eq!(invoked["writes"].as_array().unwrap().len(),1); assert!(store.get_plugin_events(&p2.manifest).unwrap().is_empty());
    let approval=json!({"package_sha256":hash2,"invocation_id":invoked["invocation_id"],"confirmed":true});
    expect(&client,&admin,Method::Post,"/test-plugin/writes/approve",approval.clone(),Status::Ok);
    assert_eq!(store.get_plugin_events(&p2.manifest).unwrap().len(),1);
    expect(&client,&admin,Method::Post,"/test-plugin/writes/approve",approval,Status::Conflict);
    let history=expect(&client,&admin,Method::Get,"/test-plugin/history",Value::Null,Status::Ok);
    assert!(history["history"].as_array().unwrap().iter().any(|h|h["action"]=="writes_approved"));
    assert!(!history.to_string().contains("Synthetic annotation"));
    let pending=expect(&client,&admin,Method::Post,"/test-plugin/invoke",json!({"package_sha256":hash2}),Status::Ok);
    expect(&client,&admin,Method::Post,"/test-plugin/revoke",json!({"package_sha256":hash2,"confirmed":true}),Status::Ok);
    expect(&client,&admin,Method::Post,"/test-plugin/writes/approve",json!({"package_sha256":hash2,"invocation_id":pending["invocation_id"],"confirmed":true}),Status::Conflict);
    expect(&client,&admin,Method::Post,"/test-plugin/consent",json!({"package_sha256":hash2,"confirmed":true}),Status::Conflict);
    expect(&client,&admin,Method::Delete,"/test-plugin",json!({"package_sha256":hash2,"confirmed":true}),Status::Ok);
    assert!(store.get_plugin_events(&p2.manifest).unwrap().is_empty());
    assert!(store.get_bucket("unrelated-activity").is_ok());
    expect(&client,&admin,Method::Post,"/install",json!({"package":p2,"module_bytes":m2}),Status::Conflict);
}
#[test]
fn release_gates_and_signature_review_fail_closed() {
    let (package,module)=package("1.0.0",true);
    let (client,_,admin,_)=setup(&[],false);
    expect(&client,&admin,Method::Post,"/install",json!({"package":package,"module_bytes":module,"ambient_network":true}),Status::UnprocessableEntity);
    let status=expect(&client,&admin,Method::Get,"/status",Value::Null,Status::Ok);
    assert_eq!(status["runtime_available"],false);
    expect(&client,&admin,Method::Post,"/install",json!({"package":package,"module_bytes":module}),Status::ServiceUnavailable);
    let (client,_,admin,_)=setup(&[&package],true);
    let mut changed=module.clone();changed[0]^=1;
    expect(&client,&admin,Method::Post,"/install",json!({"package":package,"module_bytes":changed}),Status::Forbidden);
    let mut changed=package.clone();changed.manifest.description.push('!');
    expect(&client,&admin,Method::Post,"/install",json!({"package":changed,"module_bytes":module}),Status::Forbidden);
}
