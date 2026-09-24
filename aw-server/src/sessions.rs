//! In-memory, revocable local API sessions. Credentials never enter configuration.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rocket::http::{Method, RawStr, Status};
use subtle::ConstantTimeEq;

pub const TOKEN_HEADER: &str = "X-PeakActivity-Token";
const LIFETIME: Duration = Duration::from_secs(15 * 60);
const GRACE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq)]
pub enum Scope {
    Ingest(Vec<String>),
    Read,
    Query,
    Admin,
    AiSend,
}

#[derive(PartialEq)]
pub struct Access {
    pub rotated: Option<String>,
    pub ingest_only: bool,
    pub ai_send_only: bool,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Access").field("rotated", &self.rotated.is_some())
            .field("ingest_only", &self.ingest_only)
            .field("ai_send_only", &self.ai_send_only).finish()
    }
}

impl Scope {
    fn permits(&self, method: Method, path: &str) -> bool {
        if path == "/api/0/info" && method == Method::Get { return true; }
        match self {
            Self::Admin => true,
            Self::Read => method == Method::Get && (path.starts_with("/api/0/buckets/")
                || path.trim_end_matches('/') == "/api/0/buckets" || path.trim_end_matches('/') == "/api/0/export"),
            Self::Query => method == Method::Post && path.trim_end_matches('/') == "/api/0/query",
            Self::AiSend => (method == Method::Post && path == "/api/0/ai/send")
                || (method == Method::Post && path.strip_prefix("/api/0/ai/native-preview/")
                    .is_some_and(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))),
            Self::Ingest(prefixes) => {
                let parts: Vec<_> = path.trim_end_matches('/').split('/').collect();
                if parts.len() < 5 || parts[..4] != ["", "api", "0", "buckets"] { return false; }
                let Ok(bucket) = RawStr::new(parts[4]).percent_decode() else { return false; };
                if bucket.contains('/') || !prefixes.iter().any(|prefix| bucket.starts_with(prefix)) { return false; }
                (parts.len() == 5 && matches!(method, Method::Get | Method::Post))
                    || (parts.len() == 6 && method == Method::Post && matches!(parts[5], "heartbeat" | "events"))
            }
        }
    }
}

struct Session {
    token: String,
    refresh: Option<String>,
    previous: Option<(String, Instant)>,
    scope: Scope,
    expires: Instant,
    wall_expires: SystemTime,
    window: Instant,
    requests: u32,
}

impl Session {
    fn alive(&self, now: Instant) -> bool {
        // Instant can exclude suspend time on some platforms; also bound wall time.
        self.expires > now && self.wall_expires > SystemTime::now()
    }
}

#[derive(Clone)]
pub struct Sessions {
    sessions: Arc<Mutex<Vec<Session>>>,
    origins: Vec<String>,
}

fn token() -> Result<String, &'static str> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| "Secure randomness unavailable")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl Sessions {
    pub fn new(port: u16, testing: bool) -> Self {
        let mut origins = vec![format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")];
        if testing { origins.extend(["http://127.0.0.1:27180".into(), "http://localhost:27180".into()]); }
        Self { sessions: Arc::new(Mutex::new(Vec::new())), origins }
    }

    pub fn origin_allowed(&self, origin: Option<&str>) -> bool {
        origin.is_none_or(|origin| self.origins.iter().any(|allowed| allowed == origin))
    }

    pub fn mint(&self, scope: Scope) -> Result<String, &'static str> {
        Ok(self.mint_inner(scope, false)?.0)
    }

    pub fn mint_collector(&self, scope: Scope) -> Result<(String, String), &'static str> {
        let (access, refresh) = self.mint_inner(scope, true)?;
        Ok((access, refresh.expect("collector grant")))
    }

    fn mint_inner(&self, scope: Scope, renewable: bool) -> Result<(String, Option<String>), &'static str> {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().map_err(|_| "Session store unavailable")?;
        sessions.retain(|session| session.alive(now) || session.refresh.is_some());
        // ponytail: linear constant-time comparisons, capped at 64 local clients; shard only for a larger client population.
        if sessions.len() >= 64 { return Err("Too many local sessions"); }
        let token = token()?;
        let refresh = if renewable { Some(crate::sessions::token()?) } else { None };
        sessions.push(Session { token: token.clone(), refresh: refresh.clone(), previous: None, scope,
                               expires: now + LIFETIME, wall_expires: SystemTime::now() + LIFETIME,
                               window: now, requests: 0 });
        Ok((token, refresh))
    }

    pub fn renew(&self, refresh: &str) -> Result<String, Status> {
        if refresh.len() != 64 { return Err(Status::Unauthorized); }
        let mut sessions = self.sessions.lock().map_err(|_| Status::ServiceUnavailable)?;
        let session = sessions.iter_mut().find(|session| session.refresh.as_ref().is_some_and(|secret|
            bool::from(secret.as_bytes().ct_eq(refresh.as_bytes())))).ok_or(Status::Unauthorized)?;
        let now = Instant::now();
        if now.duration_since(session.window) < Duration::from_secs(1) && session.requests >= 120 {
            return Err(Status::TooManyRequests);
        }
        if now.duration_since(session.window) >= Duration::from_secs(1) { session.window = now; session.requests = 0; }
        session.requests += 1;
        let replacement = token().map_err(|_| Status::ServiceUnavailable)?;
        session.previous = Some((std::mem::replace(&mut session.token, replacement.clone()), now + GRACE));
        session.expires = now + LIFETIME;
        session.wall_expires = SystemTime::now() + LIFETIME;
        Ok(replacement)
    }

    pub fn revoke_collector(&self, refresh: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|session| session.refresh.as_deref() != Some(refresh));
        }
    }

    pub fn revoke_all(&self) {
        if let Ok(mut sessions) = self.sessions.lock() { sessions.clear(); }
    }

    pub fn revoke_access_token(&self, token: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|session| {
                let current = bool::from(session.token.as_bytes().ct_eq(token.as_bytes()));
                let previous = session.previous.as_ref().is_some_and(|(value, _)| {
                    bool::from(value.as_bytes().ct_eq(token.as_bytes()))
                });
                !(current || previous)
            });
        }
    }

    pub fn token_alive(&self, token: &str) -> bool {
        let now = Instant::now();
        self.sessions.lock().is_ok_and(|sessions| sessions.iter().any(|session|
            session.alive(now) && (bool::from(session.token.as_bytes().ct_eq(token.as_bytes()))
                || session.previous.as_ref().is_some_and(|(previous, until)| *until > now
                    && bool::from(previous.as_bytes().ct_eq(token.as_bytes()))))))
    }

    pub fn authorize(&self, token_value: &str, method: Method, path: &str, origin: Option<&str>) -> Result<Access, Status> {
        if !self.origin_allowed(origin) { return Err(Status::Forbidden); }
        if path.contains("//") || path.split('/').any(|part| matches!(part, "." | "..")) { return Err(Status::BadRequest); }
        let now = Instant::now();
        let mut sessions = self.sessions.lock().map_err(|_| Status::ServiceUnavailable)?;
        sessions.retain(|session| session.alive(now) || session.refresh.is_some());
        let session = sessions.iter_mut().find(|session| {
            session.alive(now) && (bool::from(session.token.as_bytes().ct_eq(token_value.as_bytes())) || session.previous.as_ref().is_some_and(|(old, until)|
                *until > now && bool::from(old.as_bytes().ct_eq(token_value.as_bytes()))))
        }).ok_or(Status::Unauthorized)?;
        if !session.scope.permits(method, path) { return Err(Status::Forbidden); }
        if now.duration_since(session.window) >= Duration::from_secs(1) {
            session.window = now;
            session.requests = 0;
        }
        session.requests += 1;
        if session.requests > 120 { return Err(Status::TooManyRequests); }
        if session.expires.duration_since(now) < LIFETIME / 2 {
            let replacement = token().map_err(|_| Status::ServiceUnavailable)?;
            let previous = std::mem::replace(&mut session.token, replacement);
            session.previous = Some((previous, now + GRACE));
            session.expires = now + LIFETIME;
            session.wall_expires = SystemTime::now() + LIFETIME;
        }
        // Return the current generation for parallel requests still using the grace token.
        Ok(Access { rotated: (session.token != token_value).then(|| session.token.clone()),
                    ingest_only: matches!(&session.scope, Scope::Ingest(_)),
                    ai_send_only: matches!(&session.scope, Scope::AiSend) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_cannot_read_events_or_change_settings() {
        let sessions = Sessions::new(5600, false);
        let token = sessions.mint(Scope::Ingest(vec!["aw-watcher-window_".into()])).unwrap();
        assert!(sessions.authorize(&token, Method::Post, "/api/0/buckets/aw-watcher-window_test/heartbeat", None).is_ok());
        for (method, path) in [(Method::Get, "/api/0/buckets/aw-watcher-window_test/events"),
                              (Method::Get, "/api/0/buckets/aw-watcher-window_test/events/1/corrections"),
                              (Method::Put, "/api/0/buckets/aw-watcher-window_test/events/1"),
                              (Method::Delete, "/api/0/buckets/aw-watcher-window_test/events"),
                              (Method::Delete, "/api/0/buckets/aw-watcher-window_test/events/1"),
                              (Method::Post, "/api/0/buckets/aw-watcher-window_test/events/1/split"),
                              (Method::Post, "/api/0/buckets/aw-watcher-window_test/events/1/merge/2"),
                              (Method::Post, "/api/0/settings/privacy_filters"),
                              (Method::Post, "/api/0/buckets/other/events")] {
            assert_eq!(sessions.authorize(&token, method, path, None), Err(Status::Forbidden));
        }
    }

    #[test]
    fn ai_send_scope_can_read_native_preview_only_through_post_and_cannot_access_other_routes() {
        let sessions = Sessions::new(5600, false);
        let token = sessions.mint(Scope::AiSend).unwrap();
        let preview = format!("/api/0/ai/native-preview/{}", "a".repeat(64));
        assert!(sessions.authorize(&token, Method::Post, "/api/0/ai/send", None).is_ok());
        assert!(sessions.authorize(&token, Method::Post, &preview, None).is_ok());
        for (method, path) in [
            (Method::Get, "/api/0/ai/native-preview/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (Method::Post, "/api/0/ai/preview"),
            (Method::Get, "/api/0/ai/settings"),
            (Method::Post, "/api/0/buckets/aw-watcher-window_test/events"),
            (Method::Get, "/api/0/settings"),
            (Method::Post, "/api/0/ai/native-preview/preview_01/extra"),
            (Method::Post, "/api/0/ai/native-preview/short"),
        ] {
            assert_eq!(sessions.authorize(&token, method, path, None), Err(Status::Forbidden));
        }
    }

    #[test]
    fn native_ai_send_session_can_be_revoked_immediately_after_the_request() {
        let sessions = Sessions::new(5600, false);
        let token = sessions.mint(Scope::AiSend).unwrap();
        sessions.revoke_access_token(&token);
        assert_eq!(sessions.authorize(&token, Method::Post, "/api/0/ai/send", None), Err(Status::Unauthorized));
    }

    #[test]
    fn expiry_revocation_and_origin_are_enforced() {
        let sessions = Sessions::new(5600, false);
        let token = sessions.mint(Scope::Admin).unwrap();
        assert_eq!(sessions.authorize(&token, Method::Get, "/api/0/info", Some("http://evil.invalid")), Err(Status::Forbidden));
        sessions.sessions.lock().unwrap()[0].expires = Instant::now();
        assert_eq!(sessions.authorize(&token, Method::Get, "/api/0/info", None), Err(Status::Unauthorized));
        let token = sessions.mint(Scope::Read).unwrap();
        sessions.revoke_all();
        assert_eq!(sessions.authorize(&token, Method::Get, "/api/0/info", None), Err(Status::Unauthorized));
    }

    #[test]
    fn renewal_preserves_scope_and_rate_limit() {
        let sessions = Sessions::new(5600, false);
        let old = sessions.mint(Scope::Read).unwrap();
        sessions.sessions.lock().unwrap()[0].expires = Instant::now() + Duration::from_secs(100);
        let new = sessions.authorize(&old, Method::Get, "/api/0/info", None).unwrap().rotated.unwrap();
        assert_eq!(sessions.authorize(&old, Method::Get, "/api/0/info", None).unwrap().rotated, Some(new.clone()));
        assert_eq!(sessions.authorize(&new, Method::Post, "/api/0/settings/x", None), Err(Status::Forbidden));
        sessions.sessions.lock().unwrap()[0].requests = 120;
        assert_eq!(sessions.authorize(&new, Method::Get, "/api/0/info", None), Err(Status::TooManyRequests));
    }

    #[test]
    fn collector_can_resume_after_sleep_but_not_after_native_revocation() {
        let sessions = Sessions::new(5600, false);
        let (access, refresh) = sessions.mint_collector(Scope::Ingest(vec!["aw-watcher-afk_".into()])).unwrap();
        sessions.sessions.lock().unwrap()[0].expires = Instant::now();
        assert_eq!(sessions.authorize(&access, Method::Get, "/api/0/info", None), Err(Status::Unauthorized));
        let next = sessions.renew(&refresh).unwrap();
        assert_eq!(sessions.authorize(&next, Method::Get, "/api/0/settings", None), Err(Status::Forbidden));
        sessions.revoke_collector(&refresh);
        assert_eq!(sessions.renew(&refresh), Err(Status::Unauthorized));
    }

    #[test]
    fn wall_expiry_covers_suspend_while_monotonic_expiry_limits_clock_rollback() {
        let sessions = Sessions::new(5600, false);
        let token = sessions.mint(Scope::Read).unwrap();
        sessions.sessions.lock().unwrap()[0].wall_expires = SystemTime::UNIX_EPOCH;
        assert_eq!(sessions.authorize(&token, Method::Get, "/api/0/info", None), Err(Status::Unauthorized));
        let token = sessions.mint(Scope::Read).unwrap();
        sessions.sessions.lock().unwrap()[0].expires = Instant::now();
        assert_eq!(sessions.authorize(&token, Method::Get, "/api/0/info", None), Err(Status::Unauthorized));
    }
}
