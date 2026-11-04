//! Single-purpose recovery canister: moves liquid ICP from the canister's own default ledger
//! account to one fixed recipient, on request of one fixed caller.
//!
//! There is no recipient argument, no generic call forwarding and no other way to move funds.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod engine;
pub mod storage;
pub mod types;

#[cfg(all(feature = "canister", target_arch = "wasm32"))]
mod canister;
