//! Circuit breaker registry.

use std::sync::{Arc, Mutex};

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use std::collections::HashMap;

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
