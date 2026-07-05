//! Request / Response transformation.

use crate::header_rewriting::HeaderRewriteChain;
use crate::http::{Method, Request, Response};
use crate::path_rewriting::PathRewrite;

// Request / Response transformation
// ---------------------------------------------------------------------------

/// A request transformation function.
#[derive(Clone)]
pub struct RequestTransform {
    transforms: Vec<RequestTransformOp>,
}

/// Individual request transformation operations.
#[derive(Debug, Clone)]
pub enum RequestTransformOp {
    /// Rewrite headers.
    RewriteHeaders(HeaderRewriteChain),
    /// Rewrite the path.
    RewritePath(PathRewrite),
    /// Set the method.
    SetMethod(Method),
    /// Set the host.
    SetHost(String),
    /// Add query parameter.
    AddQuery { key: String, value: String },
}

impl RequestTransform {
    /// Create an empty transform.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add a transform operation.
    pub fn add(&mut self, op: RequestTransformOp) {
        self.transforms.push(op);
    }

    /// Apply all transforms to a request.
    pub fn apply(&self, req: &mut Request) {
        for op in &self.transforms {
            match op {
                RequestTransformOp::RewriteHeaders(chain) => chain.apply(&mut req.headers),
                RequestTransformOp::RewritePath(rw) => req.path = rw.apply(&req.path),
                RequestTransformOp::SetMethod(m) => req.method = *m,
                RequestTransformOp::SetHost(h) => req.host.clone_from(h),
                RequestTransformOp::AddQuery { key, value } => {
                    if req.query.is_empty() {
                        req.query = format!("{key}={value}");
                    } else {
                        req.query = format!("{}&{key}={value}", req.query);
                    }
                }
            }
        }
    }

    /// Return the number of transform operations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transforms.len()
    }

    /// Return whether the transform is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

impl Default for RequestTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RequestTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestTransform")
            .field("count", &self.transforms.len())
            .finish()
    }
}

/// A response transformation function.
#[derive(Clone)]
pub struct ResponseTransform {
    transforms: Vec<ResponseTransformOp>,
}

/// Individual response transformation operations.
#[derive(Debug, Clone)]
pub enum ResponseTransformOp {
    /// Rewrite headers.
    RewriteHeaders(HeaderRewriteChain),
    /// Set the status code.
    SetStatus(u16),
    /// Replace body.
    SetBody(Vec<u8>),
}

impl ResponseTransform {
    /// Create an empty transform.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add a transform operation.
    pub fn add(&mut self, op: ResponseTransformOp) {
        self.transforms.push(op);
    }

    /// Apply all transforms to a response.
    pub fn apply(&self, resp: &mut Response) {
        for op in &self.transforms {
            match op {
                ResponseTransformOp::RewriteHeaders(chain) => chain.apply(&mut resp.headers),
                ResponseTransformOp::SetStatus(s) => resp.status = *s,
                ResponseTransformOp::SetBody(b) => resp.body.clone_from(b),
            }
        }
    }

    /// Return the number of transform operations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transforms.len()
    }

    /// Return whether the transform is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

impl Default for ResponseTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ResponseTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseTransform")
            .field("count", &self.transforms.len())
            .finish()
    }
}
