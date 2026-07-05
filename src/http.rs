//! HTTP primitives (`Method` / `Headers` / `Request` / `Response`).

// HTTP primitives
// ---------------------------------------------------------------------------

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
}

impl Method {
    /// Parse from a string slice (case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "PATCH" => Some(Self::Patch),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "TRACE" => Some(Self::Trace),
            "CONNECT" => Some(Self::Connect),
            _ => None,
        }
    }

    /// Return the canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
        }
    }
}

/// A collection of HTTP headers (case-insensitive keys).
#[derive(Debug, Clone, Default)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// Create an empty header set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or overwrite a header (key stored in lower-case).
    pub fn set(&mut self, key: &str, value: &str) {
        let lk = key.to_ascii_lowercase();
        for entry in &mut self.entries {
            if entry.0 == lk {
                value.clone_into(&mut entry.1);
                return;
            }
        }
        self.entries.push((lk, value.to_owned()));
    }

    /// Get the first value for a key (case-insensitive lookup).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        let lk = key.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|e| e.0 == lk)
            .map(|e| e.1.as_str())
    }

    /// Remove all values for a key.
    pub fn remove(&mut self, key: &str) {
        let lk = key.to_ascii_lowercase();
        self.entries.retain(|e| e.0 != lk);
    }

    /// Return the number of headers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the header set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over (key, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|e| (e.0.as_str(), e.1.as_str()))
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        let lk = key.to_ascii_lowercase();
        self.entries.iter().any(|e| e.0 == lk)
    }

    /// Append a header (allows duplicates).
    pub fn append(&mut self, key: &str, value: &str) {
        self.entries
            .push((key.to_ascii_lowercase(), value.to_owned()));
    }

    /// Get all values for a key.
    #[must_use]
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        let lk = key.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| e.0 == lk)
            .map(|e| e.1.as_str())
            .collect()
    }
}

/// An HTTP request representation.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub host: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub query: String,
}

impl Request {
    /// Create a new request with the given method and path.
    #[must_use]
    pub fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            path: path.to_owned(),
            host: String::new(),
            headers: Headers::new(),
            body: Vec::new(),
            query: String::new(),
        }
    }

    /// Set the host.
    #[must_use]
    pub fn with_host(mut self, host: &str) -> Self {
        host.clone_into(&mut self.host);
        self
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.set(key, value);
        self
    }

    /// Set the body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Set the query string.
    #[must_use]
    pub fn with_query(mut self, query: &str) -> Self {
        query.clone_into(&mut self.query);
        self
    }
}

/// An HTTP response representation.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    /// Create a response with the given status code.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.set(key, value);
        self
    }

    /// Set the body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}
