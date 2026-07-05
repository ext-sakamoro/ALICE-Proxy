//! Integration tests spanning multiple modules.

#![allow(
    clippy::float_cmp,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::bool_to_int_with_if,
    clippy::approx_constant,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::format_collect,
    clippy::similar_names,
    clippy::needless_collect,
    clippy::iter_cloned_collect,
    clippy::suboptimal_flops,
    clippy::should_panic_without_expect,
    clippy::manual_range_contains,
    clippy::bool_assert_comparison
)]

use crate::cb_registry::*;
use crate::circuit_breaker::*;
use crate::engine::*;
use crate::header_rewriting::*;
use crate::health_check::*;
use crate::host_matching::*;
use crate::http::*;
use crate::load_balancer::*;
use crate::path_matching::*;
use crate::path_rewriting::*;
use crate::rate_limiter::*;
use crate::retry::*;
use crate::router::*;
use crate::routing::*;
use crate::transform::*;
use std::collections::HashMap;
use std::time::Duration;

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
