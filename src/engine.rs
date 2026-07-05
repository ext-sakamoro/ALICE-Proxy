//! Proxy engine (`ProxyResult` / `ProxyError` / `ProxyEngine`).

use std::sync::Arc;

use crate::cb_registry::CircuitBreakerRegistry;
use crate::circuit_breaker::CircuitBreakerConfig;
use crate::http::Request;
use crate::http::{Headers, Method};
use crate::load_balancer::{LbStrategy, LoadBalancer, Upstream};
use crate::router::Router;
use crate::routing::Route;
// transform types unused here
use std::collections::HashMap;

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
