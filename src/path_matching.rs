//! Path matching (`PathMatcher`).

// Path matching
// ---------------------------------------------------------------------------

/// Path matching strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatcher {
    /// Exact match.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Suffix match.
    Suffix(String),
    /// Contains substring.
    Contains(String),
    /// Simple glob: `*` matches any segment, `**` matches multiple segments.
    Glob(String),
    /// Matches any path.
    Any,
}

impl PathMatcher {
    /// Test whether a path matches this matcher.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(p) => path == p,
            Self::Prefix(p) => path.starts_with(p.as_str()),
            Self::Suffix(s) => path.ends_with(s.as_str()),
            Self::Contains(s) => path.contains(s.as_str()),
            Self::Glob(pattern) => glob_match(pattern, path),
            Self::Any => true,
        }
    }
}

/// Simple glob matching supporting `*` (one segment) and `**` (multiple segments).
fn glob_match(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    glob_match_parts(&pat_parts, &path_parts)
}

fn glob_match_parts(pat: &[&str], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        // ** matches zero or more segments
        for i in 0..=path.len() {
            if glob_match_parts(&pat[1..], &path[i..]) {
                return true;
            }
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    let seg_matches = pat[0] == "*" || pat[0] == path[0];
    seg_matches && glob_match_parts(&pat[1..], &path[1..])
}
