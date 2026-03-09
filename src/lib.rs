#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::option_if_let_else
)]

//! ALICE-Proxy: L7 reverse proxy engine.
//!
//! Provides routing rules, header rewriting, path matching, upstream selection,
//! load balancing, request/response transformation, and circuit breaker.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// HTTP primitives
// ---------------------------------------------------------------------------

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
}

impl Method {
    /// Parse from a string slice (case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "PATCH" => Some(Self::Patch),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "TRACE" => Some(Self::Trace),
            "CONNECT" => Some(Self::Connect),
            _ => None,
        }
    }

    /// Return the canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
        }
    }
}

/// A collection of HTTP headers (case-insensitive keys).
#[derive(Debug, Clone, Default)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// Create an empty header set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or overwrite a header (key stored in lower-case).
    pub fn set(&mut self, key: &str, value: &str) {
        let lk = key.to_ascii_lowercase();
        for entry in &mut self.entries {
            if entry.0 == lk {
                value.clone_into(&mut entry.1);
                return;
            }
        }
        self.entries.push((lk, value.to_owned()));
    }

    /// Get the first value for a key (case-insensitive lookup).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        let lk = key.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|e| e.0 == lk)
            .map(|e| e.1.as_str())
    }

    /// Remove all values for a key.
    pub fn remove(&mut self, key: &str) {
        let lk = key.to_ascii_lowercase();
        self.entries.retain(|e| e.0 != lk);
    }

    /// Return the number of headers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the header set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over (key, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|e| (e.0.as_str(), e.1.as_str()))
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        let lk = key.to_ascii_lowercase();
        self.entries.iter().any(|e| e.0 == lk)
    }

    /// Append a header (allows duplicates).
    pub fn append(&mut self, key: &str, value: &str) {
        self.entries
            .push((key.to_ascii_lowercase(), value.to_owned()));
    }

    /// Get all values for a key.
    #[must_use]
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        let lk = key.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| e.0 == lk)
            .map(|e| e.1.as_str())
            .collect()
    }
}

/// An HTTP request representation.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub host: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub query: String,
}

impl Request {
    /// Create a new request with the given method and path.
    #[must_use]
    pub fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            path: path.to_owned(),
            host: String::new(),
            headers: Headers::new(),
            body: Vec::new(),
            query: String::new(),
        }
    }

    /// Set the host.
    #[must_use]
    pub fn with_host(mut self, host: &str) -> Self {
        host.clone_into(&mut self.host);
        self
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.set(key, value);
        self
    }

    /// Set the body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Set the query string.
    #[must_use]
    pub fn with_query(mut self, query: &str) -> Self {
        query.clone_into(&mut self.query);
        self
    }
}

/// An HTTP response representation.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    /// Create a response with the given status code.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.set(key, value);
        self
    }

    /// Set the body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

/// Path matching strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatcher {
    /// Exact match.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Suffix match.
    Suffix(String),
    /// Contains substring.
    Contains(String),
    /// Simple glob: `*` matches any segment, `**` matches multiple segments.
    Glob(String),
    /// Matches any path.
    Any,
}

impl PathMatcher {
    /// Test whether a path matches this matcher.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(p) => path == p,
            Self::Prefix(p) => path.starts_with(p.as_str()),
            Self::Suffix(s) => path.ends_with(s.as_str()),
            Self::Contains(s) => path.contains(s.as_str()),
            Self::Glob(pattern) => glob_match(pattern, path),
            Self::Any => true,
        }
    }
}

/// Simple glob matching supporting `*` (one segment) and `**` (multiple segments).
fn glob_match(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    glob_match_parts(&pat_parts, &path_parts)
}

fn glob_match_parts(pat: &[&str], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        // ** matches zero or more segments
        for i in 0..=path.len() {
            if glob_match_parts(&pat[1..], &path[i..]) {
                return true;
            }
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    let seg_matches = pat[0] == "*" || pat[0] == path[0];
    seg_matches && glob_match_parts(&pat[1..], &path[1..])
}

// ---------------------------------------------------------------------------
// Host matching
// ---------------------------------------------------------------------------

/// Host matching strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatcher {
    /// Exact host match.
    Exact(String),
    /// Suffix match (e.g. `.example.com`).
    Suffix(String),
    /// Match any host.
    Any,
}

impl HostMatcher {
    /// Test whether a host matches.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(h) => host == h,
            Self::Suffix(s) => host.ends_with(s.as_str()),
            Self::Any => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Header rewriting
// ---------------------------------------------------------------------------

/// A single header rewrite operation.
#[derive(Debug, Clone)]
pub enum HeaderRewrite {
    /// Set (or overwrite) a header.
    Set { key: String, value: String },
    /// Remove a header.
    Remove { key: String },
    /// Rename a header key (preserving the value).
    Rename { from: String, to: String },
    /// Append a value to an existing header (or create it).
    Append { key: String, value: String },
}

impl HeaderRewrite {
    /// Apply the rewrite to a header set.
    pub fn apply(&self, headers: &mut Headers) {
        match self {
            Self::Set { key, value } => headers.set(key, value),
            Self::Remove { key } => headers.remove(key),
            Self::Rename { from, to } => {
                if let Some(v) = headers.get(from).map(str::to_owned) {
                    headers.remove(from);
                    headers.set(to, &v);
                }
            }
            Self::Append { key, value } => headers.append(key, value),
        }
    }
}

/// A chain of header rewrite operations.
#[derive(Debug, Clone, Default)]
pub struct HeaderRewriteChain {
    rewrites: Vec<HeaderRewrite>,
}

impl HeaderRewriteChain {
    /// Create an empty chain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rewrites: Vec::new(),
        }
    }

    /// Add a rewrite operation.
    pub fn add(&mut self, rewrite: HeaderRewrite) {
        self.rewrites.push(rewrite);
    }

    /// Apply all rewrites in order.
    pub fn apply(&self, headers: &mut Headers) {
        for rw in &self.rewrites {
            rw.apply(headers);
        }
    }

    /// Return the number of rewrites.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rewrites.len()
    }

    /// Return whether the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Path rewriting
// ---------------------------------------------------------------------------

/// Path rewrite strategy.
#[derive(Debug, Clone)]
pub enum PathRewrite {
    /// No rewrite.
    None,
    /// Strip a prefix from the path.
    StripPrefix(String),
    /// Add a prefix to the path.
    AddPrefix(String),
    /// Replace the entire path.
    Replace(String),
    /// Replace a prefix with another.
    ReplacePrefix { from: String, to: String },
}

impl PathRewrite {
    /// Apply path rewriting.
    #[must_use]
    pub fn apply(&self, path: &str) -> String {
        match self {
            Self::None => path.to_owned(),
            Self::StripPrefix(prefix) => {
                if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                    if rest.is_empty() {
                        "/".to_owned()
                    } else {
                        rest.to_owned()
                    }
                } else {
                    path.to_owned()
                }
            }
            Self::AddPrefix(prefix) => format!("{prefix}{path}"),
            Self::Replace(new_path) => new_path.clone(),
            Self::ReplacePrefix { from, to } => {
                if let Some(rest) = path.strip_prefix(from.as_str()) {
                    format!("{to}{rest}")
                } else {
                    path.to_owned()
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Upstream & load balancing
// ---------------------------------------------------------------------------

/// A single upstream backend.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub address: String,
    pub weight: u32,
}

impl Upstream {
    /// Create a new upstream with the given address and weight.
    #[must_use]
    pub fn new(address: &str, weight: u32) -> Self {
        Self {
            address: address.to_owned(),
            weight,
        }
    }
}

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    /// Round-robin selection.
    RoundRobin,
    /// Weighted round-robin.
    WeightedRoundRobin,
    /// Least connections (approximated via counter).
    LeastConnections,
    /// IP/host hash.
    IpHash,
    /// Always select the first upstream.
    First,
    /// Random selection (deterministic via counter for reproducibility).
    Random,
}

/// Load balancer that selects an upstream from a pool.
#[derive(Debug)]
pub struct LoadBalancer {
    upstreams: Vec<Upstream>,
    strategy: LbStrategy,
    counter: AtomicUsize,
    connections: Vec<AtomicU64>,
}

impl LoadBalancer {
    /// Create a new load balancer.
    ///
    /// # Panics
    ///
    /// Panics if `upstreams` is empty.
    #[must_use]
    pub fn new(upstreams: Vec<Upstream>, strategy: LbStrategy) -> Self {
        assert!(!upstreams.is_empty(), "upstreams must not be empty");
        let conn_count = upstreams.len();
        let connections = (0..conn_count).map(|_| AtomicU64::new(0)).collect();
        Self {
            upstreams,
            strategy,
            counter: AtomicUsize::new(0),
            connections,
        }
    }

    /// Select an upstream index based on the strategy.
    #[must_use]
    pub fn select(&self, key: &str) -> usize {
        match self.strategy {
            LbStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed);
                idx % self.upstreams.len()
            }
            LbStrategy::WeightedRoundRobin => self.weighted_select(),
            LbStrategy::LeastConnections => self.least_connections_select(),
            LbStrategy::IpHash => self.hash_select(key),
            LbStrategy::First => 0,
            LbStrategy::Random => {
                let idx = self.counter.fetch_add(7, Ordering::Relaxed);
                idx % self.upstreams.len()
            }
        }
    }

    /// Get the upstream at the given index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Upstream> {
        self.upstreams.get(index)
    }

    /// Return the number of upstreams.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.upstreams.len()
    }

    /// Return whether the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    /// Increment the connection counter for an upstream.
    pub fn inc_connections(&self, index: usize) {
        if index < self.connections.len() {
            self.connections[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement the connection counter for an upstream.
    pub fn dec_connections(&self, index: usize) {
        if index < self.connections.len() {
            self.connections[index].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get the connection count for an upstream.
    #[must_use]
    pub fn connection_count(&self, index: usize) -> u64 {
        self.connections
            .get(index)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Return the strategy.
    #[must_use]
    pub const fn strategy(&self) -> LbStrategy {
        self.strategy
    }

    fn weighted_select(&self) -> usize {
        let total: u32 = self.upstreams.iter().map(|u| u.weight).sum();
        if total == 0 {
            return 0;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed);
        let point = (idx as u32) % total;
        let mut acc = 0u32;
        for (i, u) in self.upstreams.iter().enumerate() {
            acc += u.weight;
            if point < acc {
                return i;
            }
        }
        self.upstreams.len() - 1
    }

    fn least_connections_select(&self) -> usize {
        let mut min_idx = 0;
        let mut min_val = u64::MAX;
        for (i, c) in self.connections.iter().enumerate() {
            let v = c.load(Ordering::Relaxed);
            if v < min_val {
                min_val = v;
                min_idx = i;
            }
        }
        min_idx
    }

    fn hash_select(&self, key: &str) -> usize {
        let hash = simple_hash(key);
        (hash as usize) % self.upstreams.len()
    }
}

/// Simple FNV-1a hash for deterministic hashing without external deps.
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Request / Response transformation
// ---------------------------------------------------------------------------

/// A request transformation function.
#[derive(Clone)]
pub struct RequestTransform {
    transforms: Vec<RequestTransformOp>,
}

/// Individual request transformation operations.
#[derive(Debug, Clone)]
pub enum RequestTransformOp {
    /// Rewrite headers.
    RewriteHeaders(HeaderRewriteChain),
    /// Rewrite the path.
    RewritePath(PathRewrite),
    /// Set the method.
    SetMethod(Method),
    /// Set the host.
    SetHost(String),
    /// Add query parameter.
    AddQuery { key: String, value: String },
}

impl RequestTransform {
    /// Create an empty transform.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add a transform operation.
    pub fn add(&mut self, op: RequestTransformOp) {
        self.transforms.push(op);
    }

    /// Apply all transforms to a request.
    pub fn apply(&self, req: &mut Request) {
        for op in &self.transforms {
            match op {
                RequestTransformOp::RewriteHeaders(chain) => chain.apply(&mut req.headers),
                RequestTransformOp::RewritePath(rw) => req.path = rw.apply(&req.path),
                RequestTransformOp::SetMethod(m) => req.method = *m,
                RequestTransformOp::SetHost(h) => req.host.clone_from(h),
                RequestTransformOp::AddQuery { key, value } => {
                    if req.query.is_empty() {
                        req.query = format!("{key}={value}");
                    } else {
                        req.query = format!("{}&{key}={value}", req.query);
                    }
                }
            }
        }
    }

    /// Return the number of transform operations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transforms.len()
    }

    /// Return whether the transform is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

impl Default for RequestTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RequestTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestTransform")
            .field("count", &self.transforms.len())
            .finish()
    }
}

/// A response transformation function.
#[derive(Clone)]
pub struct ResponseTransform {
    transforms: Vec<ResponseTransformOp>,
}

/// Individual response transformation operations.
#[derive(Debug, Clone)]
pub enum ResponseTransformOp {
    /// Rewrite headers.
    RewriteHeaders(HeaderRewriteChain),
    /// Set the status code.
    SetStatus(u16),
    /// Replace body.
    SetBody(Vec<u8>),
}

impl ResponseTransform {
    /// Create an empty transform.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add a transform operation.
    pub fn add(&mut self, op: ResponseTransformOp) {
        self.transforms.push(op);
    }

    /// Apply all transforms to a response.
    pub fn apply(&self, resp: &mut Response) {
        for op in &self.transforms {
            match op {
                ResponseTransformOp::RewriteHeaders(chain) => chain.apply(&mut resp.headers),
                ResponseTransformOp::SetStatus(s) => resp.status = *s,
                ResponseTransformOp::SetBody(b) => resp.body.clone_from(b),
            }
        }
    }

    /// Return the number of transform operations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transforms.len()
    }

    /// Return whether the transform is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

impl Default for ResponseTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ResponseTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseTransform")
            .field("count", &self.transforms.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening.
    pub failure_threshold: u32,
    /// Duration to keep the circuit open before transitioning to half-open.
    pub open_duration: Duration,
    /// Number of successes in half-open needed to close.
    pub half_open_successes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            half_open_successes: 2,
        }
    }
}

/// Circuit breaker for a single upstream.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Mutex<CircuitBreakerInner>,
}

#[derive(Debug)]
struct CircuitBreakerInner {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given config.
    #[must_use]
    pub const fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Mutex::new(CircuitBreakerInner {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
            }),
        }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Check if the circuit allows a request.
    #[must_use]
    pub fn allow_request(&self) -> bool {
        let mut inner = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.state {
            CircuitState::Open => {
                if let Some(t) = inner.last_failure_time {
                    if t.elapsed() >= self.config.open_duration {
                        inner.state = CircuitState::HalfOpen;
                        inner.success_count = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::Closed | CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let mut inner = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.state {
            CircuitState::HalfOpen => {
                inner.success_count += 1;
                if inner.success_count >= self.config.half_open_successes {
                    inner.state = CircuitState::Closed;
                    inner.failure_count = 0;
                    inner.success_count = 0;
                }
            }
            CircuitState::Closed => {
                inner.failure_count = 0;
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let mut inner = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.last_failure_time = Some(Instant::now());
        match inner.state {
            CircuitState::Closed => {
                inner.failure_count += 1;
                if inner.failure_count >= self.config.failure_threshold {
                    inner.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Open;
                inner.success_count = 0;
            }
            CircuitState::Open => {}
        }
    }

    /// Get the current state.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        let inner = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.state
    }

    /// Get the current failure count.
    #[must_use]
    pub fn failure_count(&self) -> u32 {
        let inner = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.failure_count
    }

    /// Reset the circuit breaker to closed state.
    pub fn reset(&self) {
        let mut inner = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.state = CircuitState::Closed;
        inner.failure_count = 0;
        inner.success_count = 0;
        inner.last_failure_time = None;
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker registry
// ---------------------------------------------------------------------------

/// A registry of circuit breakers keyed by upstream address.
#[derive(Debug, Default)]
pub struct CircuitBreakerRegistry {
    breakers: Mutex<HashMap<String, Arc<CircuitBreaker>>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    /// Create a new registry with the given config.
    #[must_use]
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Get or create a circuit breaker for the given key.
    #[must_use]
    pub fn get_or_create(&self, key: &str) -> Arc<CircuitBreaker> {
        let mut map = self
            .breakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.entry(key.to_owned())
            .or_insert_with(|| Arc::new(CircuitBreaker::new(self.config.clone())))
            .clone()
    }

    /// Get the number of registered breakers.
    #[must_use]
    pub fn len(&self) -> usize {
        let map = self
            .breakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.len()
    }

    /// Check if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Routing rule
// ---------------------------------------------------------------------------

/// Method matching for a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodMatcher {
    /// Match a specific method.
    Exact(Method),
    /// Match any method.
    Any,
    /// Match a set of methods.
    AnyOf(Vec<Method>),
}

impl MethodMatcher {
    /// Check if the method matches.
    #[must_use]
    pub fn matches(&self, method: Method) -> bool {
        match self {
            Self::Exact(m) => *m == method,
            Self::Any => true,
            Self::AnyOf(ms) => ms.contains(&method),
        }
    }
}

/// A single routing rule.
#[derive(Debug)]
pub struct Route {
    pub name: String,
    pub method_matcher: MethodMatcher,
    pub path_matcher: PathMatcher,
    pub host_matcher: HostMatcher,
    pub priority: i32,
    pub request_header_rewrites: HeaderRewriteChain,
    pub response_header_rewrites: HeaderRewriteChain,
    pub path_rewrite: PathRewrite,
    pub upstream_addresses: Vec<String>,
}

impl Route {
    /// Create a new route with the given name.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            method_matcher: MethodMatcher::Any,
            path_matcher: PathMatcher::Any,
            host_matcher: HostMatcher::Any,
            priority: 0,
            request_header_rewrites: HeaderRewriteChain::new(),
            response_header_rewrites: HeaderRewriteChain::new(),
            path_rewrite: PathRewrite::None,
            upstream_addresses: Vec::new(),
        }
    }

    /// Check if the route matches a request.
    #[must_use]
    pub fn matches(&self, req: &Request) -> bool {
        self.method_matcher.matches(req.method)
            && self.path_matcher.matches(&req.path)
            && self.host_matcher.matches(&req.host)
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The core router that matches requests to routes.
#[derive(Debug, Default)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    /// Create an empty router.
    #[must_use]
    pub const fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Add a route.
    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
        // Sort by priority descending (higher priority first).
        self.routes.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Find the first matching route for a request.
    #[must_use]
    pub fn match_route(&self, req: &Request) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(req))
    }

    /// Return the number of routes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return whether the router has no routes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Remove a route by name. Returns true if found and removed.
    pub fn remove_route(&mut self, name: &str) -> bool {
        let before = self.routes.len();
        self.routes.retain(|r| r.name != name);
        self.routes.len() < before
    }

    /// Get all route names.
    #[must_use]
    pub fn route_names(&self) -> Vec<&str> {
        self.routes.iter().map(|r| r.name.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// Proxy engine (ties it all together)
// ---------------------------------------------------------------------------

/// Result of proxy resolution — tells the caller where to forward.
#[derive(Debug, Clone)]
pub struct ProxyResult {
    /// The selected upstream address.
    pub upstream: String,
    /// The rewritten request path.
    pub path: String,
    /// The rewritten request headers.
    pub headers: Headers,
    /// The route name that matched.
    pub route_name: String,
    /// The original host.
    pub host: String,
    /// The query string.
    pub query: String,
    /// The method.
    pub method: Method,
    /// The body.
    pub body: Vec<u8>,
}

/// Error from proxy resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// No route matched the request.
    NoRouteMatch,
    /// No upstream configured for the matched route.
    NoUpstream,
    /// Circuit breaker is open.
    CircuitOpen(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRouteMatch => write!(f, "no route matched"),
            Self::NoUpstream => write!(f, "no upstream available"),
            Self::CircuitOpen(addr) => write!(f, "circuit open for {addr}"),
        }
    }
}

/// The proxy engine that resolves requests.
#[derive(Debug)]
pub struct ProxyEngine {
    router: Router,
    load_balancers: HashMap<String, Arc<LoadBalancer>>,
    circuit_registry: CircuitBreakerRegistry,
}

impl ProxyEngine {
    /// Create a new proxy engine.
    #[must_use]
    pub fn new(circuit_config: CircuitBreakerConfig) -> Self {
        Self {
            router: Router::new(),
            load_balancers: HashMap::new(),
            circuit_registry: CircuitBreakerRegistry::new(circuit_config),
        }
    }

    /// Create with default circuit breaker settings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Add a route and its associated load balancer.
    pub fn add_route(&mut self, route: Route, lb_strategy: LbStrategy) {
        let upstreams: Vec<Upstream> = route
            .upstream_addresses
            .iter()
            .map(|a| Upstream::new(a, 1))
            .collect();
        if !upstreams.is_empty() {
            let lb = Arc::new(LoadBalancer::new(upstreams, lb_strategy));
            self.load_balancers.insert(route.name.clone(), lb);
        }
        self.router.add_route(route);
    }

    /// Add a route with weighted upstreams.
    pub fn add_route_weighted(&mut self, route: Route, weights: &[u32], lb_strategy: LbStrategy) {
        let upstreams: Vec<Upstream> = route
            .upstream_addresses
            .iter()
            .zip(weights.iter().copied().chain(std::iter::repeat(1)))
            .map(|(a, w)| Upstream::new(a, w))
            .collect();
        if !upstreams.is_empty() {
            let lb = Arc::new(LoadBalancer::new(upstreams, lb_strategy));
            self.load_balancers.insert(route.name.clone(), lb);
        }
        self.router.add_route(route);
    }

    /// Resolve a request to a `ProxyResult`.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError` if no route matches, no upstream is configured, or
    /// the circuit breaker is open.
    pub fn resolve(&self, req: &Request) -> Result<ProxyResult, ProxyError> {
        let route = self
            .router
            .match_route(req)
            .ok_or(ProxyError::NoRouteMatch)?;

        let lb = self
            .load_balancers
            .get(&route.name)
            .ok_or(ProxyError::NoUpstream)?;

        let idx = lb.select(&req.host);
        let upstream = lb.get(idx).ok_or(ProxyError::NoUpstream)?;

        // Check circuit breaker.
        let cb = self.circuit_registry.get_or_create(&upstream.address);
        if !cb.allow_request() {
            return Err(ProxyError::CircuitOpen(upstream.address.clone()));
        }

        // Apply path rewrite.
        let path = route.path_rewrite.apply(&req.path);

        // Apply header rewrites.
        let mut headers = req.headers.clone();
        route.request_header_rewrites.apply(&mut headers);

        Ok(ProxyResult {
            upstream: upstream.address.clone(),
            path,
            headers,
            route_name: route.name.clone(),
            host: req.host.clone(),
            query: req.query.clone(),
            method: req.method,
            body: req.body.clone(),
        })
    }

    /// Record success for an upstream.
    pub fn record_success(&self, upstream: &str) {
        let cb = self.circuit_registry.get_or_create(upstream);
        cb.record_success();
    }

    /// Record failure for an upstream.
    pub fn record_failure(&self, upstream: &str) {
        let cb = self.circuit_registry.get_or_create(upstream);
        cb.record_failure();
    }

    /// Get the router.
    #[must_use]
    pub const fn router(&self) -> &Router {
        &self.router
    }

    /// Get the circuit breaker registry.
    #[must_use]
    pub const fn circuit_registry(&self) -> &CircuitBreakerRegistry {
        &self.circuit_registry
    }
}

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

/// Retry policy configuration.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retries.
    pub max_retries: u32,
    /// Status codes that trigger a retry.
    pub retry_on_status: Vec<u16>,
    /// Whether to retry on connection errors.
    pub retry_on_error: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_on_status: vec![502, 503, 504],
            retry_on_error: true,
        }
    }
}

impl RetryPolicy {
    /// Check whether a response status should trigger a retry.
    #[must_use]
    pub fn should_retry_status(&self, status: u16) -> bool {
        self.retry_on_status.contains(&status)
    }

    /// Check if retries are exhausted.
    #[must_use]
    pub const fn exhausted(&self, attempt: u32) -> bool {
        attempt >= self.max_retries
    }
}

// ---------------------------------------------------------------------------
// Rate limiter (token bucket)
// ---------------------------------------------------------------------------

/// Simple token-bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: u64,
    tokens: Mutex<f64>,
    rate_per_sec: f64,
    last_refill: Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub fn new(capacity: u64, rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: Mutex::new(capacity as f64),
            rate_per_sec,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Try to acquire a token. Returns true if allowed.
    #[must_use]
    pub fn try_acquire(&self) -> bool {
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut last = self
            .last_refill
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = elapsed
            .mul_add(self.rate_per_sec, *tokens)
            .min(self.capacity as f64);
        *last = now;
        drop(last);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get the current token count (approximate).
    #[must_use]
    pub fn available_tokens(&self) -> f64 {
        let tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *tokens
    }

    /// Get the capacity.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Health status of an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Simple health tracker for upstreams.
#[derive(Debug, Default)]
pub struct HealthTracker {
    status: Mutex<HashMap<String, HealthStatus>>,
}

impl HealthTracker {
    /// Create a new health tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: Mutex::new(HashMap::new()),
        }
    }

    /// Set the health status for an upstream.
    pub fn set_status(&self, upstream: &str, status: HealthStatus) {
        let mut map = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.insert(upstream.to_owned(), status);
    }

    /// Get the health status for an upstream.
    #[must_use]
    pub fn get_status(&self, upstream: &str) -> HealthStatus {
        let map = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(upstream).copied().unwrap_or(HealthStatus::Unknown)
    }

    /// Check if an upstream is healthy (or unknown).
    #[must_use]
    pub fn is_available(&self, upstream: &str) -> bool {
        let status = self.get_status(upstream);
        matches!(status, HealthStatus::Healthy | HealthStatus::Unknown)
    }

    /// Get the number of tracked upstreams.
    #[must_use]
    pub fn len(&self) -> usize {
        let map = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.len()
    }

    /// Check if the tracker is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Method tests --

    #[test]
    fn method_parse_valid() {
        assert_eq!(Method::parse("GET"), Some(Method::Get));
        assert_eq!(Method::parse("post"), Some(Method::Post));
        assert_eq!(Method::parse("Put"), Some(Method::Put));
        assert_eq!(Method::parse("DELETE"), Some(Method::Delete));
        assert_eq!(Method::parse("PATCH"), Some(Method::Patch));
    }

    #[test]
    fn method_parse_more() {
        assert_eq!(Method::parse("HEAD"), Some(Method::Head));
        assert_eq!(Method::parse("OPTIONS"), Some(Method::Options));
        assert_eq!(Method::parse("TRACE"), Some(Method::Trace));
        assert_eq!(Method::parse("CONNECT"), Some(Method::Connect));
    }

    #[test]
    fn method_parse_invalid() {
        assert_eq!(Method::parse("INVALID"), None);
        assert_eq!(Method::parse(""), None);
    }

    #[test]
    fn method_as_str() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }

    // -- Headers tests --

    #[test]
    fn headers_set_and_get() {
        let mut h = Headers::new();
        h.set("Content-Type", "application/json");
        assert_eq!(h.get("content-type"), Some("application/json"));
        assert_eq!(h.get("Content-Type"), Some("application/json"));
    }

    #[test]
    fn headers_overwrite() {
        let mut h = Headers::new();
        h.set("X-Foo", "bar");
        h.set("X-Foo", "baz");
        assert_eq!(h.get("x-foo"), Some("baz"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn headers_remove() {
        let mut h = Headers::new();
        h.set("X-Remove", "val");
        assert!(h.contains("x-remove"));
        h.remove("X-Remove");
        assert!(!h.contains("x-remove"));
        assert!(h.is_empty());
    }

    #[test]
    fn headers_append_duplicates() {
        let mut h = Headers::new();
        h.append("X-Multi", "a");
        h.append("X-Multi", "b");
        let all = h.get_all("x-multi");
        assert_eq!(all, vec!["a", "b"]);
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn headers_iter() {
        let mut h = Headers::new();
        h.set("A", "1");
        h.set("B", "2");
        let pairs: Vec<_> = h.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn headers_get_missing() {
        let h = Headers::new();
        assert_eq!(h.get("nope"), None);
    }

    // -- PathMatcher tests --

    #[test]
    fn path_exact_match() {
        let m = PathMatcher::Exact("/api/v1/users".into());
        assert!(m.matches("/api/v1/users"));
        assert!(!m.matches("/api/v1/users/"));
    }

    #[test]
    fn path_prefix_match() {
        let m = PathMatcher::Prefix("/api/".into());
        assert!(m.matches("/api/v1"));
        assert!(m.matches("/api/"));
        assert!(!m.matches("/web/api"));
    }

    #[test]
    fn path_suffix_match() {
        let m = PathMatcher::Suffix(".json".into());
        assert!(m.matches("/data.json"));
        assert!(!m.matches("/data.xml"));
    }

    #[test]
    fn path_contains_match() {
        let m = PathMatcher::Contains("admin".into());
        assert!(m.matches("/api/admin/users"));
        assert!(!m.matches("/api/users"));
    }

    #[test]
    fn path_any_match() {
        let m = PathMatcher::Any;
        assert!(m.matches("/anything"));
        assert!(m.matches(""));
    }

    #[test]
    fn path_glob_star() {
        let m = PathMatcher::Glob("/api/*/users".into());
        assert!(m.matches("/api/v1/users"));
        assert!(m.matches("/api/v2/users"));
        assert!(!m.matches("/api/v1/v2/users"));
    }

    #[test]
    fn path_glob_double_star() {
        let m = PathMatcher::Glob("/api/**/users".into());
        assert!(m.matches("/api/v1/users"));
        assert!(m.matches("/api/v1/v2/users"));
        assert!(m.matches("/api/users"));
    }

    #[test]
    fn path_glob_exact_segment() {
        let m = PathMatcher::Glob("/api/v1/health".into());
        assert!(m.matches("/api/v1/health"));
        assert!(!m.matches("/api/v2/health"));
    }

    // -- HostMatcher tests --

    #[test]
    fn host_exact_match() {
        let m = HostMatcher::Exact("api.example.com".into());
        assert!(m.matches("api.example.com"));
        assert!(!m.matches("web.example.com"));
    }

    #[test]
    fn host_suffix_match() {
        let m = HostMatcher::Suffix(".example.com".into());
        assert!(m.matches("api.example.com"));
        assert!(m.matches("web.example.com"));
        assert!(!m.matches("example.org"));
    }

    #[test]
    fn host_any_match() {
        let m = HostMatcher::Any;
        assert!(m.matches("anything.com"));
    }

    // -- HeaderRewrite tests --

    #[test]
    fn header_rewrite_set() {
        let mut h = Headers::new();
        let rw = HeaderRewrite::Set {
            key: "X-Custom".into(),
            value: "hello".into(),
        };
        rw.apply(&mut h);
        assert_eq!(h.get("x-custom"), Some("hello"));
    }

    #[test]
    fn header_rewrite_remove() {
        let mut h = Headers::new();
        h.set("X-Remove", "val");
        let rw = HeaderRewrite::Remove {
            key: "X-Remove".into(),
        };
        rw.apply(&mut h);
        assert!(!h.contains("x-remove"));
    }

    #[test]
    fn header_rewrite_rename() {
        let mut h = Headers::new();
        h.set("X-Old", "val");
        let rw = HeaderRewrite::Rename {
            from: "X-Old".into(),
            to: "X-New".into(),
        };
        rw.apply(&mut h);
        assert!(!h.contains("x-old"));
        assert_eq!(h.get("x-new"), Some("val"));
    }

    #[test]
    fn header_rewrite_rename_missing() {
        let mut h = Headers::new();
        let rw = HeaderRewrite::Rename {
            from: "X-Missing".into(),
            to: "X-New".into(),
        };
        rw.apply(&mut h);
        assert!(!h.contains("x-new"));
    }

    #[test]
    fn header_rewrite_append() {
        let mut h = Headers::new();
        h.set("X-Foo", "a");
        let rw = HeaderRewrite::Append {
            key: "X-Foo".into(),
            value: "b".into(),
        };
        rw.apply(&mut h);
        let all = h.get_all("x-foo");
        assert_eq!(all, vec!["a", "b"]);
    }

    #[test]
    fn header_rewrite_chain() {
        let mut chain = HeaderRewriteChain::new();
        chain.add(HeaderRewrite::Set {
            key: "X-A".into(),
            value: "1".into(),
        });
        chain.add(HeaderRewrite::Set {
            key: "X-B".into(),
            value: "2".into(),
        });
        chain.add(HeaderRewrite::Remove { key: "X-A".into() });
        assert_eq!(chain.len(), 3);
        assert!(!chain.is_empty());

        let mut h = Headers::new();
        chain.apply(&mut h);
        assert!(!h.contains("x-a"));
        assert_eq!(h.get("x-b"), Some("2"));
    }

    // -- PathRewrite tests --

    #[test]
    fn path_rewrite_none() {
        let rw = PathRewrite::None;
        assert_eq!(rw.apply("/api/v1"), "/api/v1");
    }

    #[test]
    fn path_rewrite_strip_prefix() {
        let rw = PathRewrite::StripPrefix("/api".into());
        assert_eq!(rw.apply("/api/v1/users"), "/v1/users");
    }

    #[test]
    fn path_rewrite_strip_prefix_root() {
        let rw = PathRewrite::StripPrefix("/api".into());
        assert_eq!(rw.apply("/api"), "/");
    }

    #[test]
    fn path_rewrite_strip_prefix_no_match() {
        let rw = PathRewrite::StripPrefix("/web".into());
        assert_eq!(rw.apply("/api/v1"), "/api/v1");
    }

    #[test]
    fn path_rewrite_add_prefix() {
        let rw = PathRewrite::AddPrefix("/v2".into());
        assert_eq!(rw.apply("/users"), "/v2/users");
    }

    #[test]
    fn path_rewrite_replace() {
        let rw = PathRewrite::Replace("/new-path".into());
        assert_eq!(rw.apply("/old-path"), "/new-path");
    }

    #[test]
    fn path_rewrite_replace_prefix() {
        let rw = PathRewrite::ReplacePrefix {
            from: "/api/v1".into(),
            to: "/api/v2".into(),
        };
        assert_eq!(rw.apply("/api/v1/users"), "/api/v2/users");
    }

    #[test]
    fn path_rewrite_replace_prefix_no_match() {
        let rw = PathRewrite::ReplacePrefix {
            from: "/web".into(),
            to: "/api".into(),
        };
        assert_eq!(rw.apply("/api/v1"), "/api/v1");
    }

    // -- Upstream & LoadBalancer tests --

    #[test]
    fn upstream_creation() {
        let u = Upstream::new("127.0.0.1:8080", 5);
        assert_eq!(u.address, "127.0.0.1:8080");
        assert_eq!(u.weight, 5);
    }

    #[test]
    fn lb_round_robin() {
        let ups = vec![
            Upstream::new("a", 1),
            Upstream::new("b", 1),
            Upstream::new("c", 1),
        ];
        let lb = LoadBalancer::new(ups, LbStrategy::RoundRobin);
        assert_eq!(lb.select(""), 0);
        assert_eq!(lb.select(""), 1);
        assert_eq!(lb.select(""), 2);
        assert_eq!(lb.select(""), 0);
    }

    #[test]
    fn lb_first() {
        let ups = vec![Upstream::new("a", 1), Upstream::new("b", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::First);
        assert_eq!(lb.select(""), 0);
        assert_eq!(lb.select(""), 0);
    }

    #[test]
    fn lb_weighted() {
        let ups = vec![Upstream::new("a", 3), Upstream::new("b", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::WeightedRoundRobin);
        let mut counts = [0u32; 2];
        for _ in 0..40 {
            counts[lb.select("")] += 1;
        }
        // "a" has 3x the weight of "b"
        assert!(counts[0] > counts[1]);
    }

    #[test]
    fn lb_ip_hash_consistent() {
        let ups = vec![Upstream::new("a", 1), Upstream::new("b", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::IpHash);
        let idx1 = lb.select("192.168.1.1");
        let idx2 = lb.select("192.168.1.1");
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn lb_ip_hash_different_keys() {
        let ups = vec![
            Upstream::new("a", 1),
            Upstream::new("b", 1),
            Upstream::new("c", 1),
            Upstream::new("d", 1),
        ];
        let lb = LoadBalancer::new(ups, LbStrategy::IpHash);
        // Different keys should (likely) map to different upstreams
        let idx1 = lb.select("10.0.0.1");
        let idx2 = lb.select("10.0.0.200");
        // We just check they are valid indices
        assert!(idx1 < 4);
        assert!(idx2 < 4);
    }

    #[test]
    fn lb_least_connections() {
        let ups = vec![Upstream::new("a", 1), Upstream::new("b", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::LeastConnections);
        // Initially both at 0, should pick first
        assert_eq!(lb.select(""), 0);
        lb.inc_connections(0);
        // Now "a" has 1 conn, "b" has 0
        assert_eq!(lb.select(""), 1);
    }

    #[test]
    fn lb_connections_tracking() {
        let ups = vec![Upstream::new("x", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::RoundRobin);
        assert_eq!(lb.connection_count(0), 0);
        lb.inc_connections(0);
        lb.inc_connections(0);
        assert_eq!(lb.connection_count(0), 2);
        lb.dec_connections(0);
        assert_eq!(lb.connection_count(0), 1);
    }

    #[test]
    fn lb_get_and_len() {
        let ups = vec![Upstream::new("a", 1), Upstream::new("b", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::RoundRobin);
        assert_eq!(lb.len(), 2);
        assert!(!lb.is_empty());
        assert_eq!(lb.get(0).unwrap().address, "a");
        assert_eq!(lb.get(1).unwrap().address, "b");
        assert!(lb.get(2).is_none());
    }

    #[test]
    fn lb_strategy_accessor() {
        let ups = vec![Upstream::new("a", 1)];
        let lb = LoadBalancer::new(ups, LbStrategy::Random);
        assert_eq!(lb.strategy(), LbStrategy::Random);
    }

    #[test]
    #[should_panic(expected = "upstreams must not be empty")]
    fn lb_empty_panics() {
        let _ = LoadBalancer::new(vec![], LbStrategy::RoundRobin);
    }

    // -- Request / Response transform tests --

    #[test]
    fn request_transform_path() {
        let mut t = RequestTransform::new();
        t.add(RequestTransformOp::RewritePath(PathRewrite::StripPrefix(
            "/api".into(),
        )));
        let mut req = Request::new(Method::Get, "/api/users");
        t.apply(&mut req);
        assert_eq!(req.path, "/users");
    }

    #[test]
    fn request_transform_method() {
        let mut t = RequestTransform::new();
        t.add(RequestTransformOp::SetMethod(Method::Post));
        let mut req = Request::new(Method::Get, "/test");
        t.apply(&mut req);
        assert_eq!(req.method, Method::Post);
    }

    #[test]
    fn request_transform_host() {
        let mut t = RequestTransform::new();
        t.add(RequestTransformOp::SetHost("new-host.com".into()));
        let mut req = Request::new(Method::Get, "/test").with_host("old.com");
        t.apply(&mut req);
        assert_eq!(req.host, "new-host.com");
    }

    #[test]
    fn request_transform_add_query() {
        let mut t = RequestTransform::new();
        t.add(RequestTransformOp::AddQuery {
            key: "version".into(),
            value: "2".into(),
        });
        let mut req = Request::new(Method::Get, "/test");
        t.apply(&mut req);
        assert_eq!(req.query, "version=2");
    }

    #[test]
    fn request_transform_add_query_existing() {
        let mut t = RequestTransform::new();
        t.add(RequestTransformOp::AddQuery {
            key: "b".into(),
            value: "2".into(),
        });
        let mut req = Request::new(Method::Get, "/test").with_query("a=1");
        t.apply(&mut req);
        assert_eq!(req.query, "a=1&b=2");
    }

    #[test]
    fn request_transform_headers() {
        let mut chain = HeaderRewriteChain::new();
        chain.add(HeaderRewrite::Set {
            key: "X-Proxy".into(),
            value: "alice".into(),
        });
        let mut t = RequestTransform::new();
        t.add(RequestTransformOp::RewriteHeaders(chain));
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());

        let mut req = Request::new(Method::Get, "/");
        t.apply(&mut req);
        assert_eq!(req.headers.get("x-proxy"), Some("alice"));
    }

    #[test]
    fn response_transform_status() {
        let mut t = ResponseTransform::new();
        t.add(ResponseTransformOp::SetStatus(201));
        let mut resp = Response::new(200);
        t.apply(&mut resp);
        assert_eq!(resp.status, 201);
    }

    #[test]
    fn response_transform_body() {
        let mut t = ResponseTransform::new();
        t.add(ResponseTransformOp::SetBody(b"replaced".to_vec()));
        assert!(!t.is_empty());
        let mut resp = Response::new(200).with_body(b"original".to_vec());
        t.apply(&mut resp);
        assert_eq!(resp.body, b"replaced");
    }

    #[test]
    fn response_transform_headers() {
        let mut chain = HeaderRewriteChain::new();
        chain.add(HeaderRewrite::Set {
            key: "X-Served-By".into(),
            value: "alice-proxy".into(),
        });
        let mut t = ResponseTransform::new();
        t.add(ResponseTransformOp::RewriteHeaders(chain));
        let mut resp = Response::new(200);
        t.apply(&mut resp);
        assert_eq!(resp.headers.get("x-served-by"), Some("alice-proxy"));
    }

    #[test]
    fn response_transform_len() {
        let t = ResponseTransform::new();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    // -- Circuit breaker tests --

    #[test]
    fn circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::with_defaults();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(60),
            half_open_successes: 1,
        });
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn circuit_breaker_success_resets_count() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(60),
            half_open_successes: 1,
        });
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
        // Should still need 3 more failures to open
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_half_open_transition() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(1),
            half_open_successes: 2,
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // Wait for open duration
        std::thread::sleep(Duration::from_millis(5));
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn circuit_breaker_half_open_to_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(1),
            half_open_successes: 2,
        });
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        let _ = cb.allow_request(); // triggers half-open
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_half_open_failure_reopens() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(1),
            half_open_successes: 2,
        });
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        let _ = cb.allow_request();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn circuit_breaker_reset() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            half_open_successes: 1,
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    // -- Circuit breaker registry tests --

    #[test]
    fn circuit_registry_creates_new() {
        let reg = CircuitBreakerRegistry::new(CircuitBreakerConfig::default());
        let cb = reg.get_or_create("upstream-1");
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn circuit_registry_reuses_existing() {
        let reg = CircuitBreakerRegistry::new(CircuitBreakerConfig::default());
        let cb1 = reg.get_or_create("upstream-1");
        cb1.record_failure();
        let cb2 = reg.get_or_create("upstream-1");
        assert_eq!(cb2.failure_count(), 1);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn circuit_registry_empty() {
        let reg = CircuitBreakerRegistry::new(CircuitBreakerConfig::default());
        assert!(reg.is_empty());
    }

    // -- MethodMatcher tests --

    #[test]
    fn method_matcher_exact() {
        let m = MethodMatcher::Exact(Method::Get);
        assert!(m.matches(Method::Get));
        assert!(!m.matches(Method::Post));
    }

    #[test]
    fn method_matcher_any() {
        let m = MethodMatcher::Any;
        assert!(m.matches(Method::Get));
        assert!(m.matches(Method::Post));
    }

    #[test]
    fn method_matcher_any_of() {
        let m = MethodMatcher::AnyOf(vec![Method::Get, Method::Post]);
        assert!(m.matches(Method::Get));
        assert!(m.matches(Method::Post));
        assert!(!m.matches(Method::Delete));
    }

    // -- Route tests --

    #[test]
    fn route_matches_all() {
        let route = Route::new("catch-all");
        let req = Request::new(Method::Get, "/anything").with_host("example.com");
        assert!(route.matches(&req));
    }

    #[test]
    fn route_matches_specific() {
        let mut route = Route::new("api-route");
        route.method_matcher = MethodMatcher::Exact(Method::Get);
        route.path_matcher = PathMatcher::Prefix("/api".into());
        route.host_matcher = HostMatcher::Exact("api.example.com".into());

        let req = Request::new(Method::Get, "/api/users").with_host("api.example.com");
        assert!(route.matches(&req));

        let req2 = Request::new(Method::Post, "/api/users").with_host("api.example.com");
        assert_ne!(req2.method, Method::Get); // method mismatch
    }

    #[test]
    fn route_no_match_path() {
        let mut route = Route::new("api-only");
        route.path_matcher = PathMatcher::Prefix("/api".into());
        let req = Request::new(Method::Get, "/web/page");
        assert!(!route.matches(&req));
    }

    #[test]
    fn route_no_match_host() {
        let mut route = Route::new("host-specific");
        route.host_matcher = HostMatcher::Exact("api.example.com".into());
        let req = Request::new(Method::Get, "/").with_host("web.example.com");
        assert!(!route.matches(&req));
    }

    // -- Router tests --

    #[test]
    fn router_empty() {
        let router = Router::new();
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
        let req = Request::new(Method::Get, "/");
        assert!(router.match_route(&req).is_none());
    }

    #[test]
    fn router_matches_first_by_priority() {
        let mut router = Router::new();

        let mut r1 = Route::new("low");
        r1.priority = 1;
        r1.path_matcher = PathMatcher::Any;

        let mut r2 = Route::new("high");
        r2.priority = 10;
        r2.path_matcher = PathMatcher::Any;

        router.add_route(r1);
        router.add_route(r2);

        let req = Request::new(Method::Get, "/test");
        let matched = router.match_route(&req).unwrap();
        assert_eq!(matched.name, "high");
    }

    #[test]
    fn router_remove_route() {
        let mut router = Router::new();
        router.add_route(Route::new("a"));
        router.add_route(Route::new("b"));
        assert_eq!(router.len(), 2);
        assert!(router.remove_route("a"));
        assert_eq!(router.len(), 1);
        assert!(!router.remove_route("nonexistent"));
    }

    #[test]
    fn router_route_names() {
        let mut router = Router::new();
        router.add_route(Route::new("alpha"));
        router.add_route(Route::new("beta"));
        let names = router.route_names();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    // -- Request builder tests --

    #[test]
    fn request_builder() {
        let req = Request::new(Method::Post, "/submit")
            .with_host("example.com")
            .with_header("Content-Type", "application/json")
            .with_body(b"{}".to_vec())
            .with_query("debug=true");
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.path, "/submit");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.headers.get("content-type"), Some("application/json"));
        assert_eq!(req.body, b"{}");
        assert_eq!(req.query, "debug=true");
    }

    // -- Response builder tests --

    #[test]
    fn response_builder() {
        let resp = Response::new(201)
            .with_header("Location", "/new")
            .with_body(b"created".to_vec());
        assert_eq!(resp.status, 201);
        assert_eq!(resp.headers.get("location"), Some("/new"));
        assert_eq!(resp.body, b"created");
    }

    // -- ProxyEngine tests --

    #[test]
    fn proxy_engine_no_route() {
        let engine = ProxyEngine::with_defaults();
        let req = Request::new(Method::Get, "/");
        assert!(matches!(
            engine.resolve(&req),
            Err(ProxyError::NoRouteMatch)
        ));
    }

    #[test]
    fn proxy_engine_resolves() {
        let mut engine = ProxyEngine::with_defaults();
        let mut route = Route::new("api");
        route.path_matcher = PathMatcher::Prefix("/api".into());
        route.upstream_addresses = vec!["127.0.0.1:8080".into()];
        engine.add_route(route, LbStrategy::RoundRobin);

        let req = Request::new(Method::Get, "/api/users").with_host("example.com");
        let result = engine.resolve(&req).unwrap();
        assert_eq!(result.upstream, "127.0.0.1:8080");
        assert_eq!(result.route_name, "api");
        assert_eq!(result.path, "/api/users");
    }

    #[test]
    fn proxy_engine_path_rewrite() {
        let mut engine = ProxyEngine::with_defaults();
        let mut route = Route::new("strip");
        route.path_matcher = PathMatcher::Prefix("/api".into());
        route.path_rewrite = PathRewrite::StripPrefix("/api".into());
        route.upstream_addresses = vec!["backend:8080".into()];
        engine.add_route(route, LbStrategy::First);

        let req = Request::new(Method::Get, "/api/v1/users");
        let result = engine.resolve(&req).unwrap();
        assert_eq!(result.path, "/v1/users");
    }

    #[test]
    fn proxy_engine_header_rewrite() {
        let mut engine = ProxyEngine::with_defaults();
        let mut route = Route::new("headers");
        route.path_matcher = PathMatcher::Any;
        route.upstream_addresses = vec!["backend:8080".into()];
        route.request_header_rewrites.add(HeaderRewrite::Set {
            key: "X-Forwarded-For".into(),
            value: "proxy".into(),
        });
        engine.add_route(route, LbStrategy::First);

        let req = Request::new(Method::Get, "/");
        let result = engine.resolve(&req).unwrap();
        assert_eq!(result.headers.get("x-forwarded-for"), Some("proxy"));
    }

    #[test]
    fn proxy_engine_circuit_breaker_blocks() {
        let mut engine = ProxyEngine::new(CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_secs(60),
            half_open_successes: 1,
        });
        let mut route = Route::new("cb-test");
        route.path_matcher = PathMatcher::Any;
        route.upstream_addresses = vec!["failing-backend:8080".into()];
        engine.add_route(route, LbStrategy::First);

        // First two succeed in routing
        let req = Request::new(Method::Get, "/");
        assert!(engine.resolve(&req).is_ok());
        engine.record_failure("failing-backend:8080");
        assert!(engine.resolve(&req).is_ok());
        engine.record_failure("failing-backend:8080");

        // Now circuit is open
        let result = engine.resolve(&req);
        assert!(matches!(result, Err(ProxyError::CircuitOpen(_))));
    }

    #[test]
    fn proxy_engine_weighted_route() {
        let mut engine = ProxyEngine::with_defaults();
        let mut route = Route::new("weighted");
        route.path_matcher = PathMatcher::Any;
        route.upstream_addresses = vec!["a:80".into(), "b:80".into()];
        engine.add_route_weighted(route, &[3, 1], LbStrategy::WeightedRoundRobin);

        let req = Request::new(Method::Get, "/");
        let mut counts = HashMap::new();
        for _ in 0..40 {
            let r = engine.resolve(&req).unwrap();
            *counts.entry(r.upstream).or_insert(0u32) += 1;
        }
        assert!(counts["a:80"] > counts["b:80"]);
    }

    #[test]
    fn proxy_engine_record_success() {
        let engine = ProxyEngine::with_defaults();
        engine.record_failure("x");
        engine.record_success("x");
        let cb = engine.circuit_registry().get_or_create("x");
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn proxy_engine_router_accessor() {
        let mut engine = ProxyEngine::with_defaults();
        let mut route = Route::new("test");
        route.upstream_addresses = vec!["a".into()];
        engine.add_route(route, LbStrategy::First);
        assert_eq!(engine.router().len(), 1);
    }

    // -- RetryPolicy tests --

    #[test]
    fn retry_policy_defaults() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 3);
        assert!(p.should_retry_status(502));
        assert!(p.should_retry_status(503));
        assert!(p.should_retry_status(504));
        assert!(!p.should_retry_status(200));
        assert!(!p.should_retry_status(404));
    }

    #[test]
    fn retry_policy_exhausted() {
        let p = RetryPolicy {
            max_retries: 2,
            retry_on_status: vec![500],
            retry_on_error: true,
        };
        assert!(!p.exhausted(0));
        assert!(!p.exhausted(1));
        assert!(p.exhausted(2));
        assert!(p.exhausted(3));
    }

    // -- RateLimiter tests --

    #[test]
    fn rate_limiter_allows_within_capacity() {
        let rl = RateLimiter::new(5, 10.0);
        for _ in 0..5 {
            assert!(rl.try_acquire());
        }
    }

    #[test]
    fn rate_limiter_blocks_over_capacity() {
        let rl = RateLimiter::new(2, 0.0);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire());
    }

    #[test]
    fn rate_limiter_capacity() {
        let rl = RateLimiter::new(100, 50.0);
        assert_eq!(rl.capacity(), 100);
    }

    #[test]
    fn rate_limiter_available_tokens() {
        let rl = RateLimiter::new(10, 0.0);
        let initial = rl.available_tokens();
        assert!((initial - 10.0).abs() < 0.01);
        let _ = rl.try_acquire();
        let after = rl.available_tokens();
        assert!((after - 9.0).abs() < 0.1);
    }

    // -- HealthTracker tests --

    #[test]
    fn health_tracker_default_unknown() {
        let ht = HealthTracker::new();
        assert_eq!(ht.get_status("x"), HealthStatus::Unknown);
        assert!(ht.is_available("x"));
    }

    #[test]
    fn health_tracker_set_and_get() {
        let ht = HealthTracker::new();
        ht.set_status("a", HealthStatus::Healthy);
        assert_eq!(ht.get_status("a"), HealthStatus::Healthy);
        assert!(ht.is_available("a"));
    }

    #[test]
    fn health_tracker_unhealthy() {
        let ht = HealthTracker::new();
        ht.set_status("b", HealthStatus::Unhealthy);
        assert!(!ht.is_available("b"));
    }

    #[test]
    fn health_tracker_len() {
        let ht = HealthTracker::new();
        assert!(ht.is_empty());
        ht.set_status("a", HealthStatus::Healthy);
        assert_eq!(ht.len(), 1);
        assert!(!ht.is_empty());
    }

    // -- ProxyError display tests --

    #[test]
    fn proxy_error_display() {
        assert_eq!(format!("{}", ProxyError::NoRouteMatch), "no route matched");
        assert_eq!(
            format!("{}", ProxyError::NoUpstream),
            "no upstream available"
        );
        assert_eq!(
            format!("{}", ProxyError::CircuitOpen("x".into())),
            "circuit open for x"
        );
    }

    // -- Hash function test --

    #[test]
    fn simple_hash_deterministic() {
        let h1 = simple_hash("hello");
        let h2 = simple_hash("hello");
        assert_eq!(h1, h2);
        let h3 = simple_hash("world");
        assert_ne!(h1, h3);
    }

    // -- Integration test: full proxy pipeline --

    #[test]
    fn integration_full_pipeline() {
        let mut engine = ProxyEngine::with_defaults();

        // API route
        let mut api_route = Route::new("api");
        api_route.method_matcher = MethodMatcher::AnyOf(vec![Method::Get, Method::Post]);
        api_route.path_matcher = PathMatcher::Prefix("/api/".into());
        api_route.host_matcher = HostMatcher::Suffix(".example.com".into());
        api_route.path_rewrite = PathRewrite::StripPrefix("/api".into());
        api_route.request_header_rewrites.add(HeaderRewrite::Set {
            key: "X-Forwarded-Proto".into(),
            value: "https".into(),
        });
        api_route.upstream_addresses = vec!["backend-1:8080".into(), "backend-2:8080".into()];
        engine.add_route(api_route, LbStrategy::RoundRobin);

        // Static route
        let mut static_route = Route::new("static");
        static_route.path_matcher = PathMatcher::Prefix("/static/".into());
        static_route.upstream_addresses = vec!["cdn:80".into()];
        static_route.priority = -1; // lower priority
        engine.add_route(static_route, LbStrategy::First);

        // Test API route
        let req = Request::new(Method::Get, "/api/users").with_host("api.example.com");
        let result = engine.resolve(&req).unwrap();
        assert!(result.upstream.starts_with("backend-"));
        assert_eq!(result.path, "/users");
        assert_eq!(result.headers.get("x-forwarded-proto"), Some("https"));

        // Test static route
        let req2 = Request::new(Method::Get, "/static/logo.png");
        let result2 = engine.resolve(&req2).unwrap();
        assert_eq!(result2.upstream, "cdn:80");

        // Test no match
        let req3 = Request::new(Method::Get, "/unknown");
        assert!(engine.resolve(&req3).is_err());
    }

    #[test]
    fn integration_circuit_breaker_recovery() {
        let mut engine = ProxyEngine::new(CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_millis(1),
            half_open_successes: 1,
        });
        let mut route = Route::new("recovery");
        route.path_matcher = PathMatcher::Any;
        route.upstream_addresses = vec!["srv:80".into()];
        engine.add_route(route, LbStrategy::First);

        let req = Request::new(Method::Get, "/");

        // Trigger open
        engine.record_failure("srv:80");
        engine.record_failure("srv:80");
        assert!(engine.resolve(&req).is_err());

        // Wait for half-open
        std::thread::sleep(Duration::from_millis(5));
        assert!(engine.resolve(&req).is_ok());

        // Record success to close
        engine.record_success("srv:80");
        assert!(engine.resolve(&req).is_ok());
    }

    // -- Debug trait tests --

    #[test]
    fn debug_impls() {
        let rt = RequestTransform::new();
        let _ = format!("{rt:?}");
        let resp_t = ResponseTransform::new();
        let _ = format!("{resp_t:?}");
    }

    // -- Default trait tests --

    #[test]
    fn default_impls() {
        let _ = RequestTransform::default();
        let _ = ResponseTransform::default();
        let _ = HeaderRewriteChain::default();
        let _ = CircuitBreakerConfig::default();
    }
}
