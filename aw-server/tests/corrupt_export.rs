#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::Datastore;
use aw_models::{Bucket, Event};
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use chrono::{Duration, Utc};
use rocket::http::{ContentType, Header, Status};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::PathBuf;

const BUCKET_ID: &str = "synthetic-corrupt-export";
const CORRUPT_MARKER: &str = "synthetic-private-corrupt-export-marker";
const HEALTHY_MARKER: &str = "synthetic-private-healthy-partial-export";

struct Fixture {
    datastore: Datastore,
    path: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.datastore.lock();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn corrupt_exports_return_typed_errors_without_partial_activity_and_preserve_reads() {
    let path = std::env::temp_dir().join(format!(
        "peakactivity-corrupt-export-{}.db",
        uuid::Uuid::new_v4(),
    ));
    let key = "synthetic-corrupt-export-key-".repeat(3);
    let datastore =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
    let mut fixture = Fixture { datastore, path };
    fixture
        .datastore
        .create_bucket(&Bucket {
            bid: None,
            id: BUCKET_ID.into(),
            _type: "test".into(),
            client: "corrupt-export-test".into(),
            hostname: "synthetic".into(),
            created: None,
            data: Default::default(),
            metadata: Default::default(),
            events: None,
            last_updated: None,
        })
        .unwrap();
    let start = "2026-01-01T00:00:00Z"
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    let events = fixture
        .datastore
        .insert_events(
            BUCKET_ID,
            &[
                Event::new(
                    start,
                    Duration::seconds(1),
                    json!({"app": CORRUPT_MARKER}).as_object().unwrap().clone(),
                ),
                Event::new(
                    start + Duration::hours(1),
                    Duration::seconds(1),
                    json!({"app": HEALTHY_MARKER}).as_object().unwrap().clone(),
                ),
            ],
        )
        .unwrap();
    fixture.datastore.lock().unwrap();
    let conn = Connection::open(&fixture.path).unwrap();
    conn.pragma_update(None, "key", key.as_str()).unwrap();
    // A BLOB forces row decoding to fail; silently dropping it would yield a partial export.
    let corrupt = format!("{{{CORRUPT_MARKER}").into_bytes();
    assert_eq!(
        conn.execute(
            "UPDATE events SET data = ?1 WHERE id = ?2",
            params![corrupt, events[0].id.unwrap()]
        )
        .unwrap(),
        1
    );
    drop(conn);
    fixture.datastore =
        Datastore::open_encrypted(fixture.path.to_string_lossy().into_owned(), key).unwrap();

    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(
        ServerState {
            datastore: fixture.datastore.clone(),
            asset_resolver: AssetResolver::new(None),
            device_id: "synthetic".into(),
        },
        config,
    ))
    .unwrap();
    let host = Header::new("Host", "localhost:5600");
    let auth = Header::new("Authorization", format!("Bearer {admin}"));

    for route in [
        "/api/0/export".to_string(),
        format!("/api/0/buckets/{BUCKET_ID}/export"),
    ] {
        let response = client
            .get(route.as_str())
            .header(host.clone())
            .header(auth.clone())
            .dispatch();
        let status = response.status();
        let content_type = response.content_type();
        let body = response.into_string().unwrap();
        assert_eq!(status, Status::InternalServerError, "{route}: {body}");
        assert_eq!(
            content_type,
            Some(ContentType::JSON),
            "{route} must return the datastore error, not a panic catcher: {body}"
        );
        let error: Value =
            serde_json::from_str(&body).expect("export failure must be a typed JSON error");
        let fields = error
            .as_object()
            .expect("export failure must be an error object");
        assert_eq!(
            fields.len(),
            1,
            "export failure must contain no partial artifact: {body}"
        );
        let message = error["message"]
            .as_str()
            .expect("export failure must identify the stored-event read error");
        assert!(
            message.contains("Stored events") && message.contains("read"),
            "{route}: {body}"
        );
        assert!(
            !body.contains(CORRUPT_MARKER) && !body.contains(HEALTHY_MARKER),
            "export failure leaked activity: {body}"
        );

        let healthy = client
            .get(format!(
                "/api/0/buckets/{BUCKET_ID}/events/{}",
                events[1].id.unwrap()
            ))
            .header(host.clone())
            .header(auth.clone())
            .dispatch();
        assert_eq!(
            healthy.status(),
            Status::Ok,
            "{route} must leave the datastore worker usable"
        );
        assert_eq!(
            serde_json::from_str::<Event>(&healthy.into_string().unwrap()).unwrap(),
            events[1]
        );
    }
}
