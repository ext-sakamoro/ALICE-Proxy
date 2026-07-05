//! ALICE-Proxy: L7 reverse proxy engine.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::option_if_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::wildcard_imports,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_lossless,
    clippy::return_self_not_must_use
)]

pub mod cb_registry;
pub mod circuit_breaker;
pub mod engine;
pub mod header_rewriting;
pub mod health_check;
pub mod host_matching;
pub mod http;
pub mod load_balancer;
pub mod path_matching;
pub mod path_rewriting;
pub mod prelude;
pub mod rate_limiter;
pub mod retry;
pub mod router;
pub mod routing;
pub mod transform;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::cb_registry::*;
pub use crate::circuit_breaker::*;
pub use crate::engine::*;
pub use crate::header_rewriting::*;
pub use crate::health_check::*;
pub use crate::host_matching::*;
pub use crate::http::*;
pub use crate::load_balancer::*;
pub use crate::path_matching::*;
pub use crate::path_rewriting::*;
pub use crate::rate_limiter::*;
pub use crate::retry::*;
pub use crate::router::*;
pub use crate::routing::*;
pub use crate::transform::*;
