//! Path rewriting (`PathRewrite`).

// Path rewriting
// ---------------------------------------------------------------------------

/// Path rewrite strategy.
#[derive(Debug, Clone)]
pub enum PathRewrite {
    /// No rewrite.
    None,
    /// Strip a prefix from the path.
    StripPrefix(String),
    /// Add a prefix to the path.
    AddPrefix(String),
    /// Replace the entire path.
    Replace(String),
    /// Replace a prefix with another.
    ReplacePrefix { from: String, to: String },
}

impl PathRewrite {
    /// Apply path rewriting.
    #[must_use]
    pub fn apply(&self, path: &str) -> String {
        match self {
            Self::None => path.to_owned(),
            Self::StripPrefix(prefix) => {
                if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                    if rest.is_empty() {
                        "/".to_owned()
                    } else {
                        rest.to_owned()
                    }
                } else {
                    path.to_owned()
                }
            }
            Self::AddPrefix(prefix) => format!("{prefix}{path}"),
            Self::Replace(new_path) => new_path.clone(),
            Self::ReplacePrefix { from, to } => {
                if let Some(rest) = path.strip_prefix(from.as_str()) {
                    format!("{to}{rest}")
                } else {
                    path.to_owned()
                }
            }
        }
    }
}
