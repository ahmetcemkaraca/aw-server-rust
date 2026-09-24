//! Shared capture consent and minimization contract for storage and Rust collectors.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::Event;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CapturePolicy {
    pub revision: u64,
    pub recording: bool,
    pub paused_until: Option<DateTime<Utc>>,
    pub window: bool,
    pub idle: bool,
    pub browser: bool,
    pub titles: bool,
    pub urls: bool,
    pub paths: bool,
    pub excluded_apps: Vec<String>,
    pub excluded_domains: Vec<String>,
    pub effective_from: DateTime<Utc>,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            revision: 0,
            recording: false, paused_until: None, window: true, idle: true,
            browser: false, titles: false, urls: false, paths: false,
            excluded_apps: vec!["1password".into(), "bitwarden".into(), "keepass".into(), "keychain".into()],
            excluded_domains: Vec::new(), effective_from: Utc::now(),
        }
    }
}

impl CapturePolicy {
    pub fn active(&self, now: DateTime<Utc>) -> bool {
        self.recording && now >= self.effective_from && (self.window || self.idle || self.browser)
            && self.paused_until.is_none_or(|until| now >= until)
    }

    pub fn validate(&mut self) -> Result<(), &'static str> {
        if self.excluded_apps.len() > 200 || self.excluded_domains.len() > 200 {
            return Err("At most 200 app and domain exclusions are allowed");
        }
        for app in &mut self.excluded_apps {
            *app = app.trim().to_lowercase();
            if app.is_empty() || app.len() > 256 || app.chars().any(char::is_control) {
                return Err("App exclusions must contain 1 to 256 printable characters");
            }
        }
        for domain in &mut self.excluded_domains {
            if domain.is_empty() || domain.len() > 253 || domain.chars().any(char::is_control) || domain.contains(['/', ':', '@', '?', '#']) {
                return Err("Domain exclusions must be host names without paths or credentials");
            }
            let parsed = url::Url::parse(&format!("https://{domain}"))
                .map_err(|_| "Invalid excluded domain")?;
            *domain = parsed.host_str().ok_or("Invalid excluded domain")?
                .trim_end_matches('.').to_lowercase();
        }
        self.excluded_apps.sort(); self.excluded_apps.dedup();
        self.excluded_domains.sort(); self.excluded_domains.dedup();
        Ok(())
    }

    pub fn permits_helper(&self, name: &str, now: DateTime<Utc>) -> bool {
        self.active(now) && match name {
            "aw-watcher-window" => self.window || self.browser,
            "aw-watcher-afk" => self.idle,
            "aw-awatcher" => self.window || self.browser || self.idle,
            _ => false,
        }
    }

    /// Imports bypass the recording clock only; source consent and field restrictions still apply.
    pub fn filter(&self, bucket: &str, mut event: Event, capture: bool) -> Option<Event> {
        if event.duration < chrono::Duration::zero() { return None; }
        let end = event.timestamp.checked_add_signed(event.duration)?;
        if event.timestamp.timestamp_nanos_opt().is_none() || end.timestamp_nanos_opt().is_none()
            || (capture && end > Utc::now() + chrono::Duration::seconds(5)) { return None; }
        if capture && bucket != "aw-stopwatch" {
            if !self.active(Utc::now()) { return None; }
            let boundary = self.paused_until.map_or(self.effective_from, |until| until.max(self.effective_from));
            if event.timestamp < boundary {
                if end <= boundary { return None; }
                event.timestamp = boundary;
                event.duration = end - boundary;
            }
        }
        let private = event.data.get("incognito").or_else(|| event.data.get("private"));
        if private.is_some_and(|value| value != &Value::Bool(false)) { return None; }
        if bucket == "aw-stopwatch" {
            let label = event.data.get("label").and_then(Value::as_str)?.to_string();
            let running = event.data.get("running").and_then(Value::as_bool)?;
            event.data.clear();
            event.data.insert("label".into(), Value::String(label));
            event.data.insert("running".into(), Value::Bool(running));
            return Some(event);
        }
        if bucket.starts_with("aw-watcher-afk_") {
            if !self.idle { return None; }
            let status = event.data.get("status").and_then(Value::as_str)?;
            if !matches!(status, "afk" | "not-afk") { return None; }
            event.data.retain(|field, _| field == "status");
            return Some(event);
        }
        let window_source = bucket.starts_with("aw-watcher-window_")
            || bucket == "aw-watcher-android"
            || bucket.starts_with("aw-watcher-android_");
        let browser_source = bucket.starts_with("aw-watcher-web_");
        if !window_source && !browser_source { return None; }
        let app = event.data.get("app").and_then(Value::as_str).unwrap_or("").to_lowercase();
        if self.excluded_apps.iter().any(|excluded| app.contains(excluded)) { return None; }
        // Window APIs without an explicit private-mode signal cannot promise browser privacy.
        let browser = browser_source || event.data.contains_key("url")
            || ["chrome", "chromium", "firefox", "safari", "brave", "msedge", "microsoft edge", "opera"]
                .iter().any(|name| app.contains(name));
        if browser && (!self.browser || private != Some(&Value::Bool(false))) { return None; }
        let supported = if browser { true }
            else if window_source { self.window }
            else if bucket.starts_with("aw-watcher-afk_") { self.idle }
            else { false };
        if !supported { return None; }
        if let Some(value) = event.data.get("url") {
            let mut url = url::Url::parse(value.as_str()?).ok()?;
            if !matches!(url.scheme(), "http" | "https") { return None; }
            let host = url.host_str()?.trim_end_matches('.').to_lowercase();
            if self.excluded_domains.iter().any(|domain| host == *domain || host.ends_with(&format!(".{domain}"))) {
                return None;
            }
            url.set_host(Some(&host)).ok()?;
            // origin() discards credentials, paths, queries and fragments.
            event.data.insert("url".into(), Value::String(url.origin().ascii_serialization()));
        }
        event.data.retain(|field, value| match field.as_str() {
            "incognito" | "private" => value == &Value::Bool(false),
            "app" => value.is_string(),
            "title" => self.titles && value.is_string(),
            "url" => self.urls && value.is_string(),
            "path" => self.paths && value.is_string(),
            _ => false,
        });
        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(data: Value) -> Event {
        Event::new(Utc::now(), chrono::Duration::zero(), data.as_object().unwrap().clone())
    }

    #[test]
    fn defaults_do_not_record_and_pause_replay_is_rejected() {
        let mut policy = CapturePolicy::default();
        let old = event(json!({"app":"Editor","title":"secret"}));
        assert!(policy.filter("aw-watcher-window_test", old.clone(), true).is_none());
        policy.recording = true;
        policy.effective_from = Utc::now();
        assert!(policy.filter("aw-watcher-window_test", old, true).is_none());
        let filtered = policy.filter("aw-watcher-window_test", event(json!({"app":"Editor","title":"secret","clipboard":"hidden"})), true).unwrap();
        assert_eq!(filtered.data, json!({"app":"Editor"}).as_object().unwrap().clone());
    }

    #[test]
    fn browser_requires_private_signal_and_url_is_domain_only() {
        let mut policy = CapturePolicy { recording: true, browser: true, urls: true, ..Default::default() };
        assert!(policy.filter("aw-watcher-window_test", event(json!({"app":"Firefox","url":"https://example.org/path"})), true).is_none());
        let data = json!({"app":"Chrome","incognito":false,"url":"https://user:pass@example.org/path?q=secret#fragment"});
        let filtered = policy.filter("aw-watcher-window_test", event(data), true).unwrap();
        assert_eq!(filtered.data.get("url").unwrap(), "https://example.org");
        policy.excluded_domains = vec!["EXAMPLE.ORG.".into()];
        policy.validate().unwrap();
        assert!(policy.filter("aw-watcher-window_test", event(json!({"app":"Chrome","incognito":false,"url":"https://sub.example.org./"})), true).is_none());
    }

    #[test]
    fn case_insensitive_sensitive_app_exclusion_applies_to_mobile_window_events() {
        let policy = CapturePolicy {
            recording: true,
            excluded_apps: vec!["com.example.bank".into()],
            ..Default::default()
        };
        let event = event(json!({"app":"Com.Example.Bank", "package":"Com.Example.Bank"}));
        assert!(policy.filter("aw-watcher-android", event, true).is_none());
    }

    #[test]
    fn android_usage_bucket_keeps_only_the_minimized_app_field() {
        let policy = CapturePolicy { recording: true, ..Default::default() };
        let event = event(json!({"app":"Editor", "package":"com.example.editor", "classname":"PrivateWindow"}));
        let filtered = policy.filter("aw-watcher-android", event, true).unwrap();
        assert_eq!(filtered.data, json!({"app":"Editor"}).as_object().unwrap().clone());
    }

    #[test]
    fn idle_interval_does_not_reintroduce_time_before_resume() {
        let now = Utc::now();
        let boundary = now - chrono::Duration::seconds(5);
        let policy = CapturePolicy { recording: true, effective_from: boundary, ..Default::default() };
        let idle = Event::new(now - chrono::Duration::seconds(20), chrono::Duration::seconds(20),
                              json!({"status":"afk"}).as_object().unwrap().clone());
        let clipped = policy.filter("aw-watcher-afk_test", idle, true).unwrap();
        assert_eq!(clipped.timestamp, boundary);
        assert_eq!(clipped.duration, chrono::Duration::seconds(5));
    }

    #[test]
    fn url_fields_cannot_bypass_source_consent() {
        let policy = CapturePolicy { recording: true, idle: false, browser: true, ..Default::default() };
        let data = json!({"status":"afk", "app":"Chrome", "incognito":false, "url":"https://example.org"});
        assert!(policy.filter("aw-watcher-afk_test", event(data.clone()), true).is_none());
        assert!(policy.filter("unknown_test", event(data), true).is_none());
    }

    #[test]
    fn manual_stopwatch_keeps_only_user_entered_fields_when_tracking_is_off() {
        let policy = CapturePolicy::default();
        let value = event(json!({"label":"Planning", "running":true, "path":"/private/file"}));
        let stored = policy.filter("aw-stopwatch", value, true).unwrap();
        assert_eq!(stored.data, json!({"label":"Planning", "running":true}).as_object().unwrap().clone());
        assert!(!policy.active(Utc::now()));
    }
}
