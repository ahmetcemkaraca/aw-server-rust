extern crate aw_models;
extern crate chrono;
extern crate gethostname;
extern crate reqwest;
extern crate serde_json;
extern crate tokio;

pub mod blocking;
pub mod classes;
pub mod queries;
pub mod single_instance;

use std::{collections::{HashMap, HashSet}, error::Error};

use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::{json, Map};
use single_instance::SingleInstance;
use std::net::{IpAddr, Ipv6Addr, TcpStream};
use std::time::Duration;
use std::sync::Mutex;

pub use aw_models::{Bucket, BucketMetadata, Event, CapturePolicy};

pub struct AwClient {
    client: reqwest::Client,
    api_key: Mutex<Option<String>>,
    refresh_key: Option<String>,
    capture_policy: Option<CapturePolicy>,
    capture_continuous: Mutex<HashSet<String>>,
    #[allow(dead_code)]
    single_instance: SingleInstance,
    pub baseurl: reqwest::Url,
    pub name: String,
    pub hostname: String,
}

impl std::fmt::Debug for AwClient {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "AwClient(baseurl={:?})", self.baseurl)
    }
}

fn get_hostname() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|address| address.is_loopback())
}

fn build_client(api_key: Option<String>) -> Result<reqwest::Client, Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    if let Some(api_key) = api_key {
        let mut header_value = HeaderValue::from_str(&format!("Bearer {api_key}"))?;
        header_value.set_sensitive(true);
        headers.insert(AUTHORIZATION, header_value);
    }

    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .default_headers(headers)
        .build()?)
}

impl AwClient {
    async fn send_success(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, reqwest::Error> {
        if let Some(key) = self.api_key.lock().unwrap().as_ref() {
            let mut value = HeaderValue::from_str(&format!("Bearer {key}")).expect("validated API key");
            value.set_sensitive(true);
            request = request.header(AUTHORIZATION, value);
        }
        let retry = request.try_clone();
        let mut response = request.send().await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let (Some(refresh), Some(retry)) = (&self.refresh_key, retry) {
                let renewal = self.client.post(format!("{}api/0/session/refresh", self.baseurl))
                    .json(&json!({"refresh_token": refresh})).send().await?;
                if renewal.status().is_success() {
                    let value: serde_json::Value = renewal.json().await?;
                    if let Some(token) = value.get("access_token").and_then(|value| value.as_str()) {
                        if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                            *self.api_key.lock().unwrap() = Some(token.to_string());
                            let mut header = HeaderValue::from_str(&format!("Bearer {token}")).expect("hex token");
                            header.set_sensitive(true);
                            response = retry.header(AUTHORIZATION, header).send().await?;
                        }
                    }
                }
            }
        }
        if let Some(value) = response.headers().get("X-PeakActivity-Token").and_then(|value| value.to_str().ok()) {
            if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                *self.api_key.lock().unwrap() = Some(value.to_string());
            }
        }
        response.error_for_status()
    }

    pub fn new(host: &str, port: u16, name: &str) -> Result<AwClient, Box<dyn Error>> {
        Self::new_with_api_key(host, port, name, None)
    }

    pub fn new_with_api_key(
        host: &str,
        port: u16,
        name: &str,
        api_key: Option<String>,
    ) -> Result<AwClient, Box<dyn Error>> {
        if !is_loopback_host(host) {
            return Err("The local API client only accepts loopback hosts".into());
        }
        let host_authority = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let baseurl = reqwest::Url::parse(&format!("http://{host_authority}:{port}"))?;
        if baseurl.scheme() != "http"
            || !baseurl.host_str().is_some_and(is_loopback_host)
            || !baseurl.username().is_empty()
            || baseurl.password().is_some()
            || baseurl.path() != "/"
            || baseurl.query().is_some()
            || baseurl.fragment().is_some()
        {
            return Err("The local API client only accepts an exact loopback origin".into());
        }
        let hostname = get_hostname();
        let capture_policy = if std::env::var("PEAKACTIVITY_CAPTURE").as_deref() == Ok("1") {
            let mut policy: CapturePolicy = serde_json::from_str(&std::env::var("PEAKACTIVITY_CAPTURE_POLICY")?)?;
            policy.validate()?;
            Some(policy)
        } else { None };
        let api_key = match std::env::var("PEAKACTIVITY_API_TOKEN") {
            Ok(token) => {
                if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("Invalid local capture credential".into());
                }
                let expected = reqwest::Url::parse(&std::env::var("PEAKACTIVITY_API_ORIGIN")?)?;
                if expected.origin() != baseurl.origin()
                    || !expected.username().is_empty()
                    || expected.password().is_some()
                    || expected.path() != "/"
                    || expected.query().is_some()
                    || expected.fragment().is_some()
                {
                    return Err("Refusing to send a local capture credential to a different server".into());
                }
                Some(token)
            }
            Err(_) => api_key,
        };
        let client = build_client(api_key.clone())?;
        //TODO: change localhost string to 127.0.0.1 for feature parity
        let single_instance_name = format!("{}-at-{}-on-{}", name, host, port);
        let single_instance = single_instance::SingleInstance::new(single_instance_name.as_str())?;

        Ok(AwClient {
            client,
            api_key: Mutex::new(api_key),
            capture_policy,
            capture_continuous: Mutex::new(HashSet::new()),
            refresh_key: std::env::var("PEAKACTIVITY_API_TOKEN").ok().and_then(|_| std::env::var("PEAKACTIVITY_API_REFRESH").ok()),
            single_instance,
            baseurl,
            name: name.to_string(),
            hostname,
        })
    }

    pub async fn get_bucket(&self, bucketname: &str) -> Result<Bucket, reqwest::Error> {
        let url = format!("{}api/0/buckets/{}", self.baseurl, bucketname);
        let bucket = self.send_success(self.client.get(url))
            .await?
            .json()
            .await?;
        Ok(bucket)
    }

    pub async fn get_buckets(&self) -> Result<HashMap<String, Bucket>, reqwest::Error> {
        let url = format!("{}api/0/buckets/", self.baseurl);
        self.send_success(self.client.get(url)).await?.json().await
    }

    pub async fn create_bucket(&self, bucket: &Bucket) -> Result<(), reqwest::Error> {
        let url = format!("{}api/0/buckets/{}", self.baseurl, bucket.id);
        self.send_success(self.client.post(url).json(bucket)).await?;
        Ok(())
    }

    pub async fn create_bucket_simple(
        &self,
        bucketname: &str,
        buckettype: &str,
    ) -> Result<(), reqwest::Error> {
        let bucket = Bucket {
            bid: None,
            id: bucketname.to_string(),
            client: self.name.clone(),
            _type: buckettype.to_string(),
            hostname: self.hostname.clone(),
            data: Map::default(),
            metadata: BucketMetadata::default(),
            events: None,
            created: None,
            last_updated: None,
        };
        self.create_bucket(&bucket).await
    }

    pub async fn delete_bucket(&self, bucketname: &str) -> Result<(), reqwest::Error> {
        let url = format!("{}api/0/buckets/{}", self.baseurl, bucketname);
        self.send_success(self.client.delete(url)).await?;
        Ok(())
    }

    pub async fn query(
        &self,
        query: &str,
        timeperiods: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    ) -> Result<Vec<serde_json::Value>, reqwest::Error> {
        let url = reqwest::Url::parse(format!("{}api/0/query", self.baseurl).as_str()).unwrap();

        // Format timeperiods as ISO8601 strings, separated by /
        let timeperiods_str: Vec<String> = timeperiods
            .iter()
            .map(|(start, stop)| (start.to_rfc3339(), stop.to_rfc3339()))
            .map(|(start, stop)| format!("{}/{}", start, stop))
            .collect();

        // Result is a sequence, one element per timeperiod
        self.send_success(self.client.post(url).json(&json!({
            "query": query.split('\n').collect::<Vec<&str>>(),
            "timeperiods": timeperiods_str,
        })))
        .await?
        .json()
        .await
    }

    pub async fn get_events(
        &self,
        bucketname: &str,
        start: Option<DateTime<Utc>>,
        stop: Option<DateTime<Utc>>,
        limit: Option<u64>,
    ) -> Result<Vec<Event>, reqwest::Error> {
        let mut url = reqwest::Url::parse(
            format!("{}api/0/buckets/{}/events", self.baseurl, bucketname).as_str(),
        )
        .unwrap();

        // Must be a better way to build URLs
        if let Some(s) = start {
            url.query_pairs_mut()
                .append_pair("start", s.to_rfc3339().as_str());
        };
        if let Some(s) = stop {
            url.query_pairs_mut()
                .append_pair("end", s.to_rfc3339().as_str());
        };
        if let Some(s) = limit {
            url.query_pairs_mut()
                .append_pair("limit", s.to_string().as_str());
        };
        self.send_success(self.client.get(url)).await?.json().await
    }

    pub async fn insert_event(
        &self,
        bucketname: &str,
        event: &Event,
    ) -> Result<(), reqwest::Error> {
        let url = format!("{}api/0/buckets/{}/events", self.baseurl, bucketname);
        let eventlist = vec![event.clone()];
        self.send_success(self.client.post(url).json(&eventlist)).await?;
        Ok(())
    }

    pub async fn insert_events(
        &self,
        bucketname: &str,
        events: Vec<Event>,
    ) -> Result<(), reqwest::Error> {
        let url = format!("{}api/0/buckets/{}/events", self.baseurl, bucketname);
        self.send_success(self.client.post(url).json(&events)).await?;
        Ok(())
    }

    pub fn filter_capture(&self, bucket: &str, event: Event) -> Option<Event> {
        match &self.capture_policy {
            Some(policy) => {
                let filtered = policy.filter(bucket, event, true);
                if filtered.is_none() { self.capture_continuous.lock().unwrap().remove(bucket); }
                filtered
            },
            None => Some(event),
        }
    }

    pub async fn heartbeat(
        &self,
        bucketname: &str,
        event: &Event,
        pulsetime: f64,
    ) -> Result<(), reqwest::Error> {
        let mut event = match self.filter_capture(bucketname, event.clone()) {
            Some(event) => event,
            None => return Ok(()),
        };
        if self.capture_policy.is_some() && !self.capture_continuous.lock().unwrap().insert(bucketname.to_string()) {
            event.data.insert("capture_break".into(), serde_json::Value::Bool(true));
        }
        let url = format!(
            "{}api/0/buckets/{}/heartbeat?pulsetime={}",
            self.baseurl, bucketname, pulsetime
        );
        self.send_success(self.client.post(url).json(&event)).await?;
        Ok(())
    }

    pub async fn delete_event(
        &self,
        bucketname: &str,
        event_id: i64,
    ) -> Result<(), reqwest::Error> {
        let url = format!(
            "{}api/0/buckets/{}/events/{}",
            self.baseurl, bucketname, event_id
        );
        self.send_success(self.client.delete(url)).await?;
        Ok(())
    }

    pub async fn get_event_count(&self, bucketname: &str) -> Result<i64, reqwest::Error> {
        let url = format!("{}api/0/buckets/{}/events/count", self.baseurl, bucketname);
        let res = self.send_success(self.client.get(url))
            .await?
            .text()
            .await?;
        let count: i64 = match res.trim().parse() {
            Ok(count) => count,
            Err(err) => panic!("could not parse get_event_count response: {err:?}"),
        };
        Ok(count)
    }

    pub async fn get_info(&self) -> Result<aw_models::Info, reqwest::Error> {
        let url = format!("{}api/0/info", self.baseurl);
        self.send_success(self.client.get(url)).await?.json().await
    }

    pub async fn get_setting(&self, setting: &str) -> Result<serde_json::Value, reqwest::Error> {
        let url = format!("{}api/0/settings/{}", self.baseurl, setting);
        self.send_success(self.client.get(url)).await?.json().await
    }

    pub async fn get_settings(&self) -> Result<aw_models::Settings, reqwest::Error> {
        let url = format!("{}api/0/settings", self.baseurl);
        self.send_success(self.client.get(url)).await?.json().await
    }

    pub async fn sync_run(&self) -> Result<serde_json::Value, reqwest::Error> {
        let url = format!("{}api/0/sync/run", self.baseurl);
        self.send_success(self.client.post(url).json(&json!({}))).await?.json().await
    }

    // TODO: make async
    pub fn wait_for_start(&self) -> Result<(), Box<dyn Error>> {
        let socket_addrs = self.baseurl.socket_addrs(|| None)?;
        let socket_addr = socket_addrs
            .first()
            .ok_or("Unable to resolve baseurl into socket address")?;

        // Check if server is running with exponential backoff
        let mut retry_delay = Duration::from_millis(100);
        let max_wait = Duration::from_secs(10);
        let mut total_wait = Duration::from_secs(0);

        while total_wait < max_wait {
            match TcpStream::connect_timeout(socket_addr, retry_delay) {
                Ok(_) => break,
                Err(_) => {
                    std::thread::sleep(retry_delay);
                    total_wait += retry_delay;
                    retry_delay *= 2;
                }
            }
        }

        if total_wait >= max_wait {
            return Err(format!(
                "Local server {} not running after 10 seconds of retrying",
                socket_addr
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod network_boundary_tests {
    use super::is_loopback_host;

    #[test]
    fn only_loopback_hosts_are_allowed_for_local_api_clients() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.8.4.2"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("203.0.113.12"));
        assert!(!is_loopback_host("example.test"));
        assert!(!is_loopback_host("127.0.0.1.example.test"));
    }
}
