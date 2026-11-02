//! Constants and Candid types of the recovery canister.
//!
//! This module has no dependency on `ic-cdk`, so the `neuron-audit` CLI can import the exact same
//! constants and wire types that the canister uses; they cannot drift apart.

use candid::{CandidType, Deserialize, Nat, Principal};
use icrc_ledger_types::icrc1::transfer::TransferError;
use serde::Serialize;

/// The existing `deposits` canister. `init` traps when installed anywhere else.
pub const SOURCE_CANISTER: &str = "hnwvc-lyaaa-aaaal-aaf6q-cai";
/// The only principal allowed to call the mutating endpoints (`sticpowner`).
pub const AUTHORIZED_CALLER: &str =
    "pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe";
/// The only recipient. Funds go to its default subaccount.
pub const DESTINATION_PRINCIPAL: &str =
    "nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae";
/// Legacy account identifier of the destination's default account (checked by the CLI).
pub const DESTINATION_ACCOUNT_ID: &str =
    "2c4f810252eef78e5e81f15a086bc7b1fc5706bacbfa13fdf4e6c1fd9ae3ac26";
/// Legacy account identifier of the source canister's default account (checked by the CLI).
pub const SOURCE_ACCOUNT_ID: &str =
    "0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed";
pub const LEDGER_CANISTER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
/// ICP ledger transfer fee. Every transfer states it explicitly and the ledger must agree.
pub const LEDGER_FEE_E8S: u64 = 10_000;
/// The first transfer: 0.1 ICP.
pub const TEST_TRANSFER_E8S: u64 = 10_000_000;

/// Lifetime cap on transfer operations (successful or not). Keeps the durable state tiny.
pub const MAX_OPERATIONS: usize = 8;
/// Length of the manifest tag stored in each memo.
pub const MANIFEST_TAG_LEN: usize = 16;
const NANOS_PER_HOUR: u64 = 3_600_000_000_000;
/// The ICP ledger deduplicates for 24 h (+2 min drift). Retries are only allowed well inside it.
pub const RETRY_WINDOW_NANOS: u64 = 12 * NANOS_PER_HOUR;
/// An in-doubt operation can only be abandoned once the ledger would reject its replay as too
/// old (24 h + 2 min), with a safety margin.
pub const ABANDON_AFTER_NANOS: u64 = 25 * NANOS_PER_HOUR;

/// Deployment-time parameters. Production code only ever uses [`Config::mainnet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub source_canister: Principal,
    pub authorized_caller: Principal,
    pub destination: Principal,
    pub ledger: Principal,
    pub fee_e8s: u64,
}

impl Config {
    pub fn mainnet() -> Result<Self, String> {
        let p = |label: &str, t: &str| {
            Principal::from_text(t).map_err(|e| format!("invalid built-in {label} `{t}`: {e}"))
        };
        Ok(Self {
            source_canister: p("source canister", SOURCE_CANISTER)?,
            authorized_caller: p("authorized caller", AUTHORIZED_CALLER)?,
            destination: p("destination", DESTINATION_PRINCIPAL)?,
            ledger: p("ledger", LEDGER_CANISTER)?,
            fee_e8s: LEDGER_FEE_E8S,
        })
    }
}

/// Argument of the `transfer` endpoint. There is deliberately no recipient field.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferRequest {
    /// Must equal the canister's `next_operation_id`. Pins the approval to one position in the
    /// sequence, so an old approved request can never be replayed.
    pub expected_operation_id: u64,
    pub amount_e8s: u64,
    /// Must equal the built-in fee and the live ledger fee.
    pub expected_fee_e8s: u64,
    /// First 16 bytes of the manifest hash; copied into the ledger memo for audit.
    pub manifest_tag: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferOk {
    pub operation_id: u64,
    pub block_index: Nat,
    /// True when the ledger answered `Duplicate`: the transfer had already been executed by an
    /// earlier attempt with identical arguments.
    pub duplicate: bool,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Unauthorized,
    ZeroAmount,
    InvalidManifestTag,
    UnexpectedFee {
        expected_e8s: u64,
        requested_e8s: u64,
    },
    UnexpectedLedgerFee {
        expected_e8s: u64,
        actual_e8s: u64,
    },
    OperationIdMismatch {
        expected_next: u64,
        requested: u64,
    },
    OperationLimitReached,
    /// Another call is in progress.
    Busy,
    /// An earlier operation has no recorded final outcome; resolve it first.
    UnresolvedOperation {
        operation_id: u64,
    },
    InsufficientFunds {
        balance_e8s: u64,
        required_e8s: u64,
    },
    /// A read-only ledger query failed; nothing was recorded or sent.
    LedgerQueryFailed {
        message: String,
    },
    /// Durable state could not be written; nothing was sent.
    StorageError {
        message: String,
    },
    /// The ledger definitively refused the transfer; no ICP moved. The operation is `Failed`.
    Ledger {
        error: TransferError,
    },
    /// The outcome is unknown. The operation stays `InDoubt`: use `retry_pending` (same
    /// arguments, deduplicated by the ledger) and check the ledger before anything else.
    Ambiguous {
        operation_id: u64,
        message: String,
    },
    NoPendingOperation,
    OperationNotPending {
        operation_id: u64,
    },
    /// The operation is too old for a safe retry; reconcile against the ledger.
    RetryWindowExpired {
        operation_id: u64,
        age_nanos: u64,
    },
    AbandonTooEarly {
        operation_id: u64,
        remaining_nanos: u64,
    },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Recorded durably before the ledger call. The outcome is not known.
    InDoubt {
        last_error: String,
    },
    Completed {
        block_index: Nat,
        duplicate: bool,
    },
    /// The ledger definitively refused it (first attempt only). No ICP moved.
    Failed {
        reason: String,
    },
    /// Declared not executed by the operator after verifying the ledger, past the dedup window.
    Abandoned,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub id: u64,
    pub amount_e8s: u64,
    pub fee_e8s: u64,
    /// Exactly the `created_at_time` and `memo` sent to the ledger on every attempt.
    pub created_at_time_nanos: u64,
    pub memo: Vec<u8>,
    pub attempts: u32,
    pub status: Status,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub version: u32,
    pub next_operation_id: u64,
    pub operations: Vec<Operation>,
}

impl State {
    pub const VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            next_operation_id: 1,
            operations: Vec::new(),
        }
    }

    /// The operation whose outcome is unknown, if any.
    pub fn unresolved(&self) -> Option<&Operation> {
        self.operations
            .iter()
            .find(|o| matches!(o.status, Status::InDoubt { .. }))
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// Public, read-only description of the fixed parameters (`get_config`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConfigView {
    pub source_canister: Principal,
    pub authorized_caller: Principal,
    pub destination: Principal,
    pub ledger: Principal,
    pub fee_e8s: u64,
    pub max_operations: u64,
}

/// Memo = operation id (8 bytes, big endian) followed by the manifest tag (16 bytes).
pub fn make_memo(operation_id: u64, tag: &[u8]) -> Vec<u8> {
    let mut m = operation_id.to_be_bytes().to_vec();
    m.extend_from_slice(tag);
    m
}
