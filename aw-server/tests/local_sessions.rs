use aw_server::{config::AWConfig, endpoints::{self, AssetResolver, ServerState}, sessions::{Scope, Sessions}};
use aw_models::{Bucket, Event, TryVec};
use chrono::{Duration, Utc};
use rocket::http::{ContentType, Header, Status};
use serde_json::json;

#[test]
fn local_api_rejects_unauthenticated_cross_origin_and_url_credentials() {
    let sessions = Sessions::new(5600, false);
    let token = sessions.mint(Scope::Admin).unwrap();
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let state = ServerState { datastore: aw_datastore::Datastore::new_in_memory(false),
                              asset_resolver: AssetResolver::new(None), device_id: "synthetic".into() };
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    assert_eq!(client.get("/api/0/info").header(Header::new("Host", "localhost:5600")).dispatch().status(), Status::Unauthorized);
    let authorized = || client.get("/api/0/info").header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {token}")));
    assert_eq!(authorized().dispatch().status(), Status::Ok);
    assert_eq!(authorized().header(Header::new("Origin", "https://evil.invalid")).dispatch().status(), Status::Forbidden);
    assert_eq!(client.get(format!("/api/0/info?token={token}")).header(Header::new("Host", "localhost:5600"))
        .header(ContentType::JSON).dispatch().status(), Status::BadRequest);
}

#[test]
fn capture_credential_cannot_replace_existing_event_ids() {
    let sessions = Sessions::new(5600, false);
    let token = sessions.mint(Scope::Ingest(vec!["aw-watcher-window_".into()])).unwrap();
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let state = ServerState { datastore: aw_datastore::Datastore::new_in_memory(false),
                              asset_resolver: AssetResolver::new(None), device_id: "synthetic".into() };
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    let result = client.post("/api/0/buckets/aw-watcher-window_test/events")
        .header(Header::new("Host", "localhost:5600"))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .header(ContentType::JSON)
        .body(r#"[{"id":7,"timestamp":"2026-09-22T10:00:00Z","duration":1,"data":{"app":"synthetic"}}]"#)
        .dispatch();
    assert_eq!(result.status(), Status::Forbidden);
}

#[test]
fn admin_can_split_and_merge_adjacent_events_through_atomic_routes() {
    let sessions = Sessions::new(5600, false);
    let token = sessions.mint(Scope::Admin).unwrap();
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let datastore = aw_datastore::Datastore::new_in_memory(false);
    let start = Utc::now() - Duration::days(1);
    let bucket = Bucket {
        bid: None,
        id: "aw-watcher-window_split".into(),
        _type: "currentwindow".into(),
        client: "test".into(),
        hostname: "test".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: Some(TryVec::new(vec![Event::new(
            start,
            Duration::seconds(30),
            json!({"app":"Editor"}).as_object().unwrap().clone(),
        )])),
        last_updated: None,
    };
    datastore.create_bucket(&bucket).unwrap();
    let original_id = datastore.get_events(&bucket.id, None, None, None).unwrap()[0].id.unwrap();
    let state = ServerState { datastore, asset_resolver: AssetResolver::new(None), device_id: "synthetic".into() };
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    let authorization = || Header::new("Authorization", format!("Bearer {token}"));
    let split_at = (start + Duration::seconds(10)).to_rfc3339();
    let split = client.post(format!("/api/0/buckets/aw-watcher-window_split/events/{original_id}/split"))
        .header(Header::new("Host", "127.0.0.1:5600"))
        .header(authorization())
        .header(ContentType::JSON)
        .body(json!({"split_at": split_at}).to_string())
        .dispatch();
    assert_eq!(split.status(), Status::Ok);
    let parts: Vec<Event> = serde_json::from_str(&split.into_string().unwrap()).unwrap();
    assert_eq!(parts.len(), 2);

    let merge = client.post(format!(
        "/api/0/buckets/aw-watcher-window_split/events/{}/merge/{}",
        parts[0].id.unwrap(), parts[1].id.unwrap(),
    ))
        .header(Header::new("Host", "127.0.0.1:5600"))
        .header(authorization())
        .dispatch();
    assert_eq!(merge.status(), Status::Ok);
    let merged: Event = serde_json::from_str(&merge.into_string().unwrap()).unwrap();
    assert_eq!(merged.duration, Duration::seconds(30));
    let history = client.get(format!(
        "/api/0/buckets/aw-watcher-window_split/events/{}/corrections",
        merged.id.unwrap(),
    ))
        .header(Header::new("Host", "127.0.0.1:5600"))
        .header(authorization())
        .dispatch();
    assert_eq!(history.status(), Status::Ok);
    assert!(history.into_string().unwrap().contains("local-ui-merge"));
}
