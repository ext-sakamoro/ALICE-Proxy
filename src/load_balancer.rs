//! Upstream + load balancing (`Upstream` / `LbStrategy` / `LoadBalancer`).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
pub fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}
