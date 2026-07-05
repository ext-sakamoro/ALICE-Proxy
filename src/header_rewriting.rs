//! Header rewriting (`HeaderRewrite` / `HeaderRewriteChain`).

use crate::http::Headers;

// Header rewriting
// ---------------------------------------------------------------------------

/// A single header rewrite operation.
#[derive(Debug, Clone)]
pub enum HeaderRewrite {
    /// Set (or overwrite) a header.
    Set { key: String, value: String },
    /// Remove a header.
    Remove { key: String },
    /// Rename a header key (preserving the value).
    Rename { from: String, to: String },
    /// Append a value to an existing header (or create it).
    Append { key: String, value: String },
}

impl HeaderRewrite {
    /// Apply the rewrite to a header set.
    pub fn apply(&self, headers: &mut Headers) {
        match self {
            Self::Set { key, value } => headers.set(key, value),
            Self::Remove { key } => headers.remove(key),
            Self::Rename { from, to } => {
                if let Some(v) = headers.get(from).map(str::to_owned) {
                    headers.remove(from);
                    headers.set(to, &v);
                }
            }
            Self::Append { key, value } => headers.append(key, value),
        }
    }
}

/// A chain of header rewrite operations.
#[derive(Debug, Clone, Default)]
pub struct HeaderRewriteChain {
    rewrites: Vec<HeaderRewrite>,
}

impl HeaderRewriteChain {
    /// Create an empty chain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rewrites: Vec::new(),
        }
    }

    /// Add a rewrite operation.
    pub fn add(&mut self, rewrite: HeaderRewrite) {
        self.rewrites.push(rewrite);
    }

    /// Apply all rewrites in order.
    pub fn apply(&self, headers: &mut Headers) {
        for rw in &self.rewrites {
            rw.apply(headers);
        }
    }

    /// Return the number of rewrites.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rewrites.len()
    }

    /// Return whether the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
    }
}
