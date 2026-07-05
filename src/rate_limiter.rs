//! Rate limiter (token bucket) (`RateLimiter`).

use std::sync::Mutex;
use std::time::Instant;

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
