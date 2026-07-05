//! Circuit breaker (`CircuitState` / `CircuitBreakerConfig` / `CircuitBreaker`).

use std::sync::Mutex;
use std::time::{Duration, Instant};

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
