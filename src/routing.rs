//! Routing rule (`MethodMatcher` / `Route`).

use crate::header_rewriting::HeaderRewriteChain;
use crate::host_matching::HostMatcher;
use crate::http::{Method, Request};
use crate::path_matching::PathMatcher;
use crate::path_rewriting::PathRewrite;

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
