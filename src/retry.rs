//! Retry policy (`RetryPolicy`).

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
