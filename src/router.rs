//! Router (`Router`).

use crate::http::Request;
use crate::routing::Route;

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
