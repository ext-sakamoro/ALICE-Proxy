//! Host matching (`HostMatcher`).

// Host matching
// ---------------------------------------------------------------------------

/// Host matching strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatcher {
    /// Exact host match.
    Exact(String),
    /// Suffix match (e.g. `.example.com`).
    Suffix(String),
    /// Match any host.
    Any,
}

impl HostMatcher {
    /// Test whether a host matches.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(h) => host == h,
            Self::Suffix(s) => host.ends_with(s.as_str()),
            Self::Any => true,
        }
    }
}
