//! Health check (`HealthStatus` / `HealthTracker`).

use std::sync::Mutex;

use std::collections::HashMap;

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
