//! Pure (offline) part of the deposits-canister recovery workflow: the manifest, its hash and
//! invariants, comparison against a live snapshot, and ledger reconciliation. No network access.

use crate::governance::fmt_e8s;
use crate::recovery::{account_id, hex};
use crate::recovery_types::*;
use anyhow::{anyhow, bail, Context, Result};
use candid::Principal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const SCHEMA: &str = "neuron-audit/deposit-recovery-manifest/v1";
pub const NETWORK: &str = "ic";
/// Mainnet API boundary nodes. The agent verifies certificates against the built-in mainnet root
/// key; nothing else is accepted.
pub const ALLOWED_IC_URLS: [&str; 3] = ["https://icp0.io", "https://ic0.app", "https://icp-api.io"];
/// Verified on 2026-11-02; a *test* manifest is refused if the live balance differs.
pub const EXPECTED_SOURCE_BALANCE_E8S: u64 = 94_233_666_604;
pub const EXPECTED_DESTINATION_BALANCE_E8S: u64 = 50_000_000;
/// Cycles below which the workflow refuses to proceed (a transfer costs a tiny fraction).
pub const MIN_CYCLES: u64 = 1_000_000_000_000;
pub const MAX_MANIFEST_AGE_SECS: u64 = 3_600;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// The first, 0.1 ICP transfer.
    Test,
    /// Everything that is left (minus the fee), only after a verified test transfer.
    Final,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Install,
    Transfer,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub name: String,
    pub ic_url: String,
    pub ledger_canister: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedAt {
    pub unix_secs: u64,
    pub utc: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub canister_id: String,
    pub account_id: String,
    pub balance_e8s: u64,
    pub status: String,
    /// Hex SHA-256 of the installed module, or null for an empty canister.
    pub module_hash: Option<String>,
    pub cycles: u64,
    /// Sorted controller snapshot; must be unchanged by the installation.
    pub controllers: Vec<String>,
    /// SHA-256 of the Candid text of the canister settings (all settings must be preserved).
    pub settings_sha256: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub principal: String,
    pub account_id: String,
    pub balance_e8s: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Wasm {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Install {
    /// Always `install`; `reinstall` and `upgrade` do not exist in this tool.
    pub mode: String,
    pub target_canister: String,
    /// Module hash the canister must have right before installation (null = empty).
    pub expected_pre_install_module_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    /// Must equal the recovery canister's `next_operation_id` at execution time.
    pub operation_id: u64,
    pub amount_e8s: u64,
    pub fee_e8s: u64,
    pub total_debit_e8s: u64,
    pub expected_source_balance_after_e8s: u64,
    pub expected_destination_balance_after_e8s: u64,
    /// Module hash the canister must have when the transfer is sent (the recovery Wasm).
    pub expected_module_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub schema: String,
    pub kind: Kind,
    pub network: Network,
    pub observed_at: ObservedAt,
    pub source: Source,
    pub destination: Destination,
    pub authorized_caller: String,
    pub wasm: Wasm,
    pub install: Install,
    pub transfer: Transfer,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub body: Body,
    /// SHA-256 of the compact JSON encoding of `body`.
    pub manifest_sha256: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

impl Body {
    pub fn sha256(&self) -> Result<String> {
        Ok(sha256_hex(&serde_json::to_vec(self)?))
    }
}

impl Manifest {
    pub fn seal(body: Body) -> Result<Self> {
        let manifest_sha256 = body.sha256()?;
        Ok(Self {
            body,
            manifest_sha256,
        })
    }

    /// The 16 bytes written into the ledger memo of the transfer.
    pub fn tag(&self) -> Result<Vec<u8>> {
        let full = parse_hex(&self.manifest_sha256, 32)?;
        full.get(..MANIFEST_TAG_LEN)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| anyhow!("manifest hash too short"))
    }

    pub fn transfer_request(&self) -> Result<TransferRequest> {
        Ok(TransferRequest {
            expected_operation_id: self.body.transfer.operation_id,
            amount_e8s: self.body.transfer.amount_e8s,
            expected_fee_e8s: self.body.transfer.fee_e8s,
            manifest_tag: self.tag()?,
        })
    }

    /// Reads a manifest and verifies that its hash matches its content.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read manifest {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let m: Manifest = serde_json::from_str(text).context("manifest is not valid")?;
        let actual = m.body.sha256()?;
        if !actual.eq_ignore_ascii_case(&m.manifest_sha256) {
            bail!(
                "manifest hash mismatch: file says {}, content hashes to {actual}; the manifest was modified",
                m.manifest_sha256
            );
        }
        Ok(m)
    }
}

pub fn parse_hex(s: &str, len: usize) -> Result<Vec<u8>> {
    if s.len() != len * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("`{s}` is not {len} bytes of hex");
    }
    (0..len)
        .map(|i| {
            s.get(2 * i..2 * i + 2)
                .and_then(|x| u8::from_str_radix(x, 16).ok())
                .ok_or_else(|| anyhow!("bad hex"))
        })
        .collect()
}

pub fn check_ic_url(url: &str) -> Result<()> {
    if !ALLOWED_IC_URLS.contains(&url.trim_end_matches('/')) {
        bail!(
            "network endpoint {url} is not an allowed IC mainnet endpoint ({})",
            ALLOWED_IC_URLS.join(", ")
        );
    }
    Ok(())
}

pub fn check_identity(principal: &Principal) -> Result<()> {
    if principal.to_text() != AUTHORIZED_CALLER {
        bail!("identity {principal} is not the authorized caller {AUTHORIZED_CALLER}; aborting");
    }
    Ok(())
}

fn principal_account_hex(text: &str) -> Result<String> {
    let p = Principal::from_text(text).map_err(|e| anyhow!("bad principal {text}: {e}"))?;
    Ok(hex(&account_id(&p, None)))
}

/// Constant-only checks (no network): every fixed identity, amount and arithmetic rule.
pub fn check_invariants(b: &Body) -> Vec<String> {
    let mut p = Vec::new();
    let mut bad = |c: bool, m: String| {
        if !c {
            p.push(m)
        }
    };
    bad(
        b.schema == SCHEMA,
        format!("unexpected schema {}", b.schema),
    );
    bad(
        b.network.name == NETWORK,
        format!("unexpected network `{}` (only `{NETWORK}`)", b.network.name),
    );
    bad(
        check_ic_url(&b.network.ic_url).is_ok(),
        format!("endpoint {} is not allowed", b.network.ic_url),
    );
    bad(
        b.network.ledger_canister == LEDGER_CANISTER,
        format!("unexpected ledger {}", b.network.ledger_canister),
    );
    bad(
        b.source.canister_id == SOURCE_CANISTER,
        format!("unexpected source canister {}", b.source.canister_id),
    );
    bad(
        b.install.target_canister == SOURCE_CANISTER,
        format!("unexpected install target {}", b.install.target_canister),
    );
    bad(
        b.source.account_id == SOURCE_ACCOUNT_ID
            && principal_account_hex(&b.source.canister_id).ok().as_deref()
                == Some(SOURCE_ACCOUNT_ID),
        "source account identifier is not the default account of the source canister".into(),
    );
    bad(
        b.destination.principal == DESTINATION_PRINCIPAL,
        format!("unexpected destination {}", b.destination.principal),
    );
    bad(
        b.destination.account_id == DESTINATION_ACCOUNT_ID
            && principal_account_hex(&b.destination.principal)
                .ok()
                .as_deref()
                == Some(DESTINATION_ACCOUNT_ID),
        "destination account identifier is not the default account of the destination principal"
            .into(),
    );
    bad(
        b.authorized_caller == AUTHORIZED_CALLER,
        format!("unexpected authorized caller {}", b.authorized_caller),
    );
    bad(
        b.source.controllers.contains(&b.authorized_caller),
        "the authorized caller is not in the controller snapshot".into(),
    );
    let mut sorted = b.source.controllers.clone();
    sorted.sort();
    sorted.dedup();
    bad(
        sorted == b.source.controllers && !sorted.is_empty(),
        "controller snapshot is empty, unsorted or has duplicates".into(),
    );
    bad(
        b.source
            .controllers
            .iter()
            .all(|c| Principal::from_text(c).is_ok()),
        "controller snapshot has an invalid principal".into(),
    );
    bad(
        b.source.status == "running",
        format!("source status is `{}`, not running", b.source.status),
    );
    bad(
        b.source.cycles >= MIN_CYCLES,
        format!(
            "source cycles {} below the minimum {MIN_CYCLES}",
            b.source.cycles
        ),
    );
    bad(
        parse_hex(&b.wasm.sha256, 32).is_ok() && b.wasm.size_bytes > 0,
        "invalid wasm hash or size".into(),
    );
    bad(
        b.source
            .module_hash
            .as_deref()
            .map(|h| parse_hex(h, 32).is_ok())
            .unwrap_or(true)
            && parse_hex(&b.source.settings_sha256, 32).is_ok(),
        "invalid module hash or settings hash".into(),
    );
    bad(
        b.install.mode == "install",
        "install mode must be `install`".into(),
    );
    bad(
        b.transfer.expected_module_hash == b.wasm.sha256,
        "transfer must require the recovery wasm hash".into(),
    );
    let t = &b.transfer;
    bad(
        t.fee_e8s == LEDGER_FEE_E8S,
        format!("unexpected fee {} e8s", t.fee_e8s),
    );
    bad(t.amount_e8s > 0, "zero amount".into());
    bad(
        t.amount_e8s.checked_add(t.fee_e8s) == Some(t.total_debit_e8s),
        "total debit is not amount + fee".into(),
    );
    bad(
        b.source.balance_e8s.checked_sub(t.total_debit_e8s)
            == Some(t.expected_source_balance_after_e8s),
        "source balance after is not balance - amount - fee (or the amount exceeds the balance)"
            .into(),
    );
    bad(
        b.destination.balance_e8s.checked_add(t.amount_e8s)
            == Some(t.expected_destination_balance_after_e8s),
        "destination balance after is not balance + amount".into(),
    );
    match b.kind {
        Kind::Test => {
            bad(
                t.amount_e8s == TEST_TRANSFER_E8S,
                format!("a test transfer must be exactly {TEST_TRANSFER_E8S} e8s"),
            );
            bad(
                b.install.expected_pre_install_module_hash.is_none(),
                "a test manifest requires an empty canister (module hash None) before install"
                    .into(),
            );
            bad(
                b.source.module_hash.is_none(),
                "a test manifest requires the observed module hash to be None".into(),
            );
            bad(
                t.operation_id == 1,
                "the test transfer is operation 1".into(),
            );
        }
        Kind::Final => {
            bad(
                t.expected_source_balance_after_e8s == 0,
                "a final transfer must sweep the whole balance (balance - fee)".into(),
            );
            bad(
                b.install.expected_pre_install_module_hash.as_deref() == Some(&b.wasm.sha256)
                    && b.source.module_hash.as_deref() == Some(&b.wasm.sha256),
                "a final manifest requires the recovery wasm to be installed already".into(),
            );
            bad(
                t.operation_id > 1,
                "the final transfer follows the test transfer".into(),
            );
        }
    }
    p
}

pub fn check_freshness(b: &Body, now_unix: u64, max_age_secs: u64) -> Result<()> {
    if b.observed_at.unix_secs > now_unix + 300 {
        bail!("manifest observation time is in the future");
    }
    let age = now_unix.saturating_sub(b.observed_at.unix_secs);
    if age > max_age_secs {
        bail!(
            "manifest is {age}s old (limit {max_age_secs}s); prepare a new manifest from fresh observations"
        );
    }
    Ok(())
}

/// Everything read from the network for one comparison. `None` = could not be read.
#[derive(Clone, Debug, Default)]
pub struct Live {
    pub running: Option<bool>,
    pub module_hash: Option<String>,
    pub cycles: Option<u64>,
    pub controllers: Vec<String>,
    pub settings_sha256: Option<String>,
    pub source_balance_e8s: u64,
    pub destination_balance_e8s: u64,
    pub ledger_fee_e8s: u64,
    pub canister_config: Option<ConfigView>,
    pub canister_state: Option<State>,
}

/// Compares the manifest with the live state; every difference is a blocking problem.
/// `require_status` demands the data that only `canister_status` (controller identity) yields.
pub fn check_live(b: &Body, stage: Stage, live: &Live, require_status: bool) -> Vec<String> {
    let mut p = Vec::new();
    let mut bad = |c: bool, m: String| {
        if !c {
            p.push(m)
        }
    };
    let expected_hash = match stage {
        Stage::Install => b.install.expected_pre_install_module_hash.clone(),
        Stage::Transfer => Some(b.transfer.expected_module_hash.clone()),
    };
    bad(
        live.module_hash == expected_hash,
        format!(
            "UNEXPECTED MODULE HASH: live {:?}, required {:?}",
            live.module_hash, expected_hash
        ),
    );
    bad(
        stage != Stage::Install || b.install.expected_pre_install_module_hash.is_none(),
        "installation is only allowed into an empty canister; `reinstall`/`upgrade` are not supported"
            .into(),
    );
    bad(
        live.controllers == b.source.controllers,
        format!(
            "controllers changed: live {:?}, manifest {:?}",
            live.controllers, b.source.controllers
        ),
    );
    match live.running {
        Some(r) => bad(r, "canister is not Running".into()),
        None if require_status => bad(false, "canister status unavailable".into()),
        None => {}
    }
    match live.settings_sha256.as_deref() {
        Some(h) => bad(
            h == b.source.settings_sha256,
            "canister settings differ from the manifest".into(),
        ),
        None if require_status => bad(false, "canister settings unavailable".into()),
        None => {}
    }
    match live.cycles {
        Some(c) => bad(
            c >= MIN_CYCLES,
            format!("cycles {c} below the minimum {MIN_CYCLES}"),
        ),
        None if require_status => bad(false, "cycles unavailable".into()),
        None => {}
    }
    bad(
        live.source_balance_e8s == b.source.balance_e8s,
        format!(
            "source balance is {} e8s, manifest says {} e8s; prepare a new manifest",
            live.source_balance_e8s, b.source.balance_e8s
        ),
    );
    bad(
        live.destination_balance_e8s == b.destination.balance_e8s,
        format!(
            "destination balance is {} e8s, manifest says {} e8s; prepare a new manifest",
            live.destination_balance_e8s, b.destination.balance_e8s
        ),
    );
    bad(
        live.ledger_fee_e8s == b.transfer.fee_e8s,
        format!(
            "ledger fee is {} e8s, expected {}",
            live.ledger_fee_e8s, b.transfer.fee_e8s
        ),
    );
    if stage == Stage::Transfer {
        match &live.canister_config {
            Some(c) => {
                let want = Config::mainnet();
                bad(
                    want.as_ref().is_ok_and(|w| {
                        c.source_canister == w.source_canister
                            && c.authorized_caller == w.authorized_caller
                            && c.destination == w.destination
                            && c.ledger == w.ledger
                            && c.fee_e8s == w.fee_e8s
                    }),
                    "the installed canister's configuration differs from the expected constants"
                        .into(),
                );
            }
            None => bad(false, "canister get_config unavailable".into()),
        }
        match &live.canister_state {
            Some(s) => {
                bad(
                    s.next_operation_id == b.transfer.operation_id,
                    format!(
                        "canister next operation id is {}, manifest requires {}",
                        s.next_operation_id, b.transfer.operation_id
                    ),
                );
                bad(
                    s.unresolved().is_none(),
                    "an earlier operation is IN DOUBT; reconcile it first".into(),
                );
                bad(
                    s.operations.len() < MAX_OPERATIONS,
                    "the canister's operation limit is reached".into(),
                );
                if b.kind == Kind::Final {
                    bad(
                        s.operations.iter().any(|o| {
                            o.amount_e8s == TEST_TRANSFER_E8S
                                && matches!(o.status, Status::Completed { .. })
                        }),
                        "no completed test transfer is recorded in the canister".into(),
                    );
                }
            }
            None => bad(false, "canister get_state unavailable".into()),
        }
    }
    p
}

/// Builds a sealed manifest from fresh observations. `kind` rules are enforced by
/// [`check_invariants`], which the caller must run on the result.
pub struct PrepareInput<'a> {
    pub kind: Kind,
    pub ic_url: &'a str,
    pub now_unix: u64,
    pub utc: String,
    pub live: &'a Live,
    pub wasm_sha256: String,
    pub wasm_size: u64,
    pub operation_id: u64,
}

pub fn build(i: PrepareInput) -> Result<Manifest> {
    let live = i.live;
    let fee = LEDGER_FEE_E8S;
    let amount = match i.kind {
        Kind::Test => TEST_TRANSFER_E8S,
        Kind::Final => live
            .source_balance_e8s
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("source balance does not cover the fee"))?,
    };
    let total = amount
        .checked_add(fee)
        .ok_or_else(|| anyhow!("amount overflow"))?;
    let source_after = live
        .source_balance_e8s
        .checked_sub(total)
        .ok_or_else(|| anyhow!("amount plus fee exceeds the source balance"))?;
    let dest_after = live
        .destination_balance_e8s
        .checked_add(amount)
        .ok_or_else(|| anyhow!("destination balance overflow"))?;
    let body = Body {
        schema: SCHEMA.into(),
        kind: i.kind,
        network: Network {
            name: NETWORK.into(),
            ic_url: i.ic_url.trim_end_matches('/').into(),
            ledger_canister: LEDGER_CANISTER.into(),
        },
        observed_at: ObservedAt {
            unix_secs: i.now_unix,
            utc: i.utc,
        },
        source: Source {
            canister_id: SOURCE_CANISTER.into(),
            account_id: SOURCE_ACCOUNT_ID.into(),
            balance_e8s: live.source_balance_e8s,
            status: if live.running == Some(true) {
                "running"
            } else {
                "not-running"
            }
            .into(),
            module_hash: live.module_hash.clone(),
            cycles: live.cycles.ok_or_else(|| anyhow!("cycles unavailable"))?,
            controllers: live.controllers.clone(),
            settings_sha256: live
                .settings_sha256
                .clone()
                .ok_or_else(|| anyhow!("settings unavailable"))?,
        },
        destination: Destination {
            principal: DESTINATION_PRINCIPAL.into(),
            account_id: DESTINATION_ACCOUNT_ID.into(),
            balance_e8s: live.destination_balance_e8s,
        },
        authorized_caller: AUTHORIZED_CALLER.into(),
        wasm: Wasm {
            sha256: i.wasm_sha256.clone(),
            size_bytes: i.wasm_size,
        },
        install: Install {
            mode: "install".into(),
            target_canister: SOURCE_CANISTER.into(),
            expected_pre_install_module_hash: live.module_hash.clone(),
        },
        transfer: Transfer {
            operation_id: i.operation_id,
            amount_e8s: amount,
            fee_e8s: fee,
            total_debit_e8s: total,
            expected_source_balance_after_e8s: source_after,
            expected_destination_balance_after_e8s: dest_after,
            expected_module_hash: i.wasm_sha256,
        },
    };
    Manifest::seal(body)
}

// ---------- reconciliation ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockEvidence {
    Verified,
    Mismatch(String),
    Unavailable(String),
    NotChecked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// Recorded Completed, block verified, both balances exactly as predicted.
    Reconciled,
    /// Recorded Completed and balances match, but the ledger block could not be verified.
    Unverified,
    /// The canister has no record of the operation and balances are untouched.
    NotSubmitted,
    /// Final ledger refusal (or abandonment) recorded and balances untouched. No ICP moved.
    NoFundsMoved,
    /// The outcome is unknown. Do NOT start another transfer.
    InDoubt,
    /// Something does not add up. Stop and investigate.
    Discrepancy,
}

#[derive(Debug, Clone)]
pub struct Reconciliation {
    pub verdict: Verdict,
    pub notes: Vec<String>,
    pub source_delta_e8s: i128,
    pub destination_delta_e8s: i128,
}

pub fn reconcile(
    b: &Body,
    next_operation_id: u64,
    operation: Option<&Operation>,
    source_now: u64,
    destination_now: u64,
    block: &BlockEvidence,
) -> Reconciliation {
    let src_delta = i128::from(source_now) - i128::from(b.source.balance_e8s);
    let dst_delta = i128::from(destination_now) - i128::from(b.destination.balance_e8s);
    let untouched = src_delta == 0 && dst_delta == 0;
    let t = &b.transfer;
    let landed = source_now == t.expected_source_balance_after_e8s
        && destination_now == t.expected_destination_balance_after_e8s;
    let mut notes = vec![format!(
        "source {} -> {} e8s (delta {src_delta}); destination {} -> {} e8s (delta {dst_delta})",
        b.source.balance_e8s, source_now, b.destination.balance_e8s, destination_now
    )];
    let verdict = match operation {
        None if next_operation_id <= t.operation_id => {
            if untouched {
                notes.push(
                    "the canister has no record of this operation; balances are unchanged".into(),
                );
                Verdict::NotSubmitted
            } else {
                notes
                    .push("balances moved although the canister recorded no such operation".into());
                Verdict::Discrepancy
            }
        }
        None => {
            notes.push(
                "the canister's operation counter advanced but the operation is missing".into(),
            );
            Verdict::Discrepancy
        }
        Some(op) => {
            let mut v = if op.amount_e8s == t.amount_e8s
                && op.fee_e8s == t.fee_e8s
                && op.id == t.operation_id
            {
                None
            } else {
                notes.push(format!(
                    "recorded operation ({} e8s, fee {}, id {}) differs from the manifest",
                    op.amount_e8s, op.fee_e8s, op.id
                ));
                Some(Verdict::Discrepancy)
            };
            if v.is_none() {
                v = Some(match &op.status {
                    Status::Completed {
                        block_index,
                        duplicate,
                    } => {
                        notes.push(format!(
                            "canister recorded Completed at block {block_index}{}",
                            if *duplicate {
                                " (ledger reported a duplicate: an earlier attempt executed)"
                            } else {
                                ""
                            }
                        ));
                        match (landed, block) {
                            (false, _) => {
                                notes.push("balances do not match the prediction".into());
                                Verdict::Discrepancy
                            }
                            (true, BlockEvidence::Verified) => Verdict::Reconciled,
                            (true, BlockEvidence::Mismatch(m)) => {
                                notes.push(format!("ledger block mismatch: {m}"));
                                Verdict::Discrepancy
                            }
                            (true, BlockEvidence::Unavailable(m)) => {
                                notes.push(format!("ledger block not verified: {m}"));
                                Verdict::Unverified
                            }
                            (true, BlockEvidence::NotChecked) => Verdict::Unverified,
                        }
                    }
                    Status::InDoubt { last_error } => {
                        notes.push(format!("canister has no final outcome: {last_error}"));
                        if landed {
                            notes.push("balances show the transfer EXECUTED; run retry_pending to record the block index (the ledger answers Duplicate)".into());
                        } else if untouched {
                            notes.push("balances are unchanged: it has probably NOT executed; retry_pending is still deduplicated by the ledger".into());
                        } else {
                            notes.push("balances are in an unexpected state".into());
                        }
                        Verdict::InDoubt
                    }
                    Status::Failed { reason } => {
                        notes.push(format!("ledger refused: {reason}"));
                        if untouched {
                            Verdict::NoFundsMoved
                        } else {
                            Verdict::Discrepancy
                        }
                    }
                    Status::Abandoned => {
                        notes.push("operator declared the operation not executed".into());
                        if untouched {
                            Verdict::NoFundsMoved
                        } else {
                            Verdict::Discrepancy
                        }
                    }
                });
            }
            v.unwrap_or(Verdict::Discrepancy)
        }
    };
    Reconciliation {
        verdict,
        notes,
        source_delta_e8s: src_delta,
        destination_delta_e8s: dst_delta,
    }
}

pub fn describe_plan(b: &Body) -> String {
    let t = &b.transfer;
    format!(
        "{:?} transfer #{}: {} ICP ({} e8s) + fee {} e8s = {} e8s debited from {}; destination {} receives exactly {} e8s. Source after: {} e8s, destination after: {} e8s.",
        b.kind,
        t.operation_id,
        fmt_e8s(t.amount_e8s.into()),
        t.amount_e8s,
        t.fee_e8s,
        t.total_debit_e8s,
        b.source.account_id,
        b.destination.account_id,
        t.amount_e8s,
        t.expected_source_balance_after_e8s,
        t.expected_destination_balance_after_e8s
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use candid::Nat;

    pub(crate) const WASM: &str =
        "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
    const SETTINGS: &str = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22";
    const OTHER_CONTROLLER: &str = "aaaaa-aa";

    pub(crate) fn live_empty() -> Live {
        let mut controllers = vec![AUTHORIZED_CALLER.to_string(), OTHER_CONTROLLER.to_string()];
        controllers.sort();
        Live {
            running: Some(true),
            module_hash: None,
            cycles: Some(4_416_243_594_000),
            controllers,
            settings_sha256: Some(SETTINGS.into()),
            source_balance_e8s: EXPECTED_SOURCE_BALANCE_E8S,
            destination_balance_e8s: EXPECTED_DESTINATION_BALANCE_E8S,
            ledger_fee_e8s: LEDGER_FEE_E8S,
            canister_config: None,
            canister_state: None,
        }
    }

    pub(crate) fn test_manifest() -> Manifest {
        build(PrepareInput {
            kind: Kind::Test,
            ic_url: "https://icp0.io",
            now_unix: 1_000_000,
            utc: "x".into(),
            live: &live_empty(),
            wasm_sha256: WASM.into(),
            wasm_size: 700_000,
            operation_id: 1,
        })
        .unwrap()
    }

    fn installed_live(next_id: u64, ops: Vec<Operation>) -> Live {
        let mut l = live_empty();
        l.module_hash = Some(WASM.into());
        let c = Config::mainnet().unwrap();
        l.canister_config = Some(ConfigView {
            source_canister: c.source_canister,
            authorized_caller: c.authorized_caller,
            destination: c.destination,
            ledger: c.ledger,
            fee_e8s: c.fee_e8s,
            max_operations: MAX_OPERATIONS as u64,
        });
        l.canister_state = Some(State {
            version: 1,
            next_operation_id: next_id,
            operations: ops,
        });
        l
    }

    fn completed_op(id: u64, amount: u64) -> Operation {
        Operation {
            id,
            amount_e8s: amount,
            fee_e8s: LEDGER_FEE_E8S,
            created_at_time_nanos: 1,
            memo: vec![],
            attempts: 1,
            status: Status::Completed {
                block_index: Nat::from(5u64),
                duplicate: false,
            },
        }
    }

    #[test]
    fn constants_are_self_consistent() {
        let m = test_manifest();
        assert_eq!(check_invariants(&m.body), Vec::<String>::new());
        // The verified account identifiers are exactly the derived default accounts.
        assert_eq!(
            principal_account_hex(SOURCE_CANISTER).unwrap(),
            SOURCE_ACCOUNT_ID
        );
        assert_eq!(
            principal_account_hex(DESTINATION_PRINCIPAL).unwrap(),
            DESTINATION_ACCOUNT_ID
        );
        assert_eq!(Config::mainnet().unwrap().fee_e8s, 10_000);
    }

    #[test]
    fn test_manifest_has_exact_e8s_arithmetic() {
        let t = test_manifest().body.transfer;
        assert_eq!(t.amount_e8s, 10_000_000);
        assert_eq!(t.total_debit_e8s, 10_010_000);
        assert_eq!(
            t.expected_source_balance_after_e8s,
            94_233_666_604 - 10_010_000
        );
        assert_eq!(t.expected_destination_balance_after_e8s, 60_000_000);
    }

    #[test]
    fn final_manifest_sweeps_balance_minus_fee() {
        let mut live = live_empty();
        live.module_hash = Some(WASM.into());
        live.source_balance_e8s = 94_233_666_604 - 10_010_000;
        live.destination_balance_e8s = 60_000_000;
        let m = build(PrepareInput {
            kind: Kind::Final,
            ic_url: "https://icp0.io",
            now_unix: 1,
            utc: "x".into(),
            live: &live,
            wasm_sha256: WASM.into(),
            wasm_size: 1,
            operation_id: 2,
        })
        .unwrap();
        assert_eq!(check_invariants(&m.body), Vec::<String>::new());
        assert_eq!(m.body.transfer.amount_e8s, 94_223_656_604 - 10_000);
        assert_eq!(m.body.transfer.expected_source_balance_after_e8s, 0);
        // A final manifest cannot be used to install.
        let problems = check_live(&m.body, Stage::Install, &installed_live(2, vec![]), true);
        assert!(problems
            .iter()
            .any(|p| p.contains("only allowed into an empty canister")));
    }

    #[test]
    fn manifest_round_trips_and_detects_any_tampering() {
        let m = test_manifest();
        let text = serde_json::to_string_pretty(&m).unwrap();
        assert_eq!(Manifest::parse(&text).unwrap(), m);

        // Edit the amount without fixing the hash.
        let tampered = text.replace("\"amount_e8s\": 10000000", "\"amount_e8s\": 94000000000");
        assert_ne!(tampered, text);
        assert!(Manifest::parse(&tampered)
            .unwrap_err()
            .to_string()
            .contains("hash mismatch"));
        // Edit the destination.
        let tampered = text.replace(DESTINATION_PRINCIPAL, AUTHORIZED_CALLER);
        assert!(Manifest::parse(&tampered)
            .unwrap_err()
            .to_string()
            .contains("hash mismatch"));
        // Unknown fields are refused.
        let extra = text.replacen("\"kind\"", "\"extra\": 1, \"kind\"", 1);
        assert!(Manifest::parse(&extra).is_err());
    }

    #[test]
    fn re_sealed_tampering_still_fails_the_invariants() {
        // An attacker who also recomputes the hash is stopped by the fixed constants.
        let mut b = test_manifest().body;
        b.destination.principal = AUTHORIZED_CALLER.into();
        assert!(!check_invariants(&b).is_empty());

        let mut b = test_manifest().body;
        b.transfer.amount_e8s = b.source.balance_e8s - LEDGER_FEE_E8S;
        b.transfer.total_debit_e8s = b.source.balance_e8s;
        b.transfer.expected_source_balance_after_e8s = 0;
        b.transfer.expected_destination_balance_after_e8s =
            b.destination.balance_e8s + b.transfer.amount_e8s;
        let p = check_invariants(&b);
        assert!(
            p.iter()
                .any(|m| m.contains("test transfer must be exactly")),
            "{p:?}"
        );

        let mut b = test_manifest().body;
        b.destination.account_id = SOURCE_ACCOUNT_ID.into();
        assert!(!check_invariants(&b).is_empty());
        let mut b = test_manifest().body;
        b.transfer.fee_e8s = 0;
        assert!(!check_invariants(&b).is_empty());
        let mut b = test_manifest().body;
        b.install.mode = "reinstall".into();
        assert!(!check_invariants(&b).is_empty());
        let mut b = test_manifest().body;
        b.install.target_canister = DESTINATION_PRINCIPAL.into();
        assert!(!check_invariants(&b).is_empty());
        let mut b = test_manifest().body;
        b.authorized_caller = DESTINATION_PRINCIPAL.into();
        assert!(!check_invariants(&b).is_empty());
        let mut b = test_manifest().body;
        b.source.module_hash = Some(WASM.into());
        assert!(!check_invariants(&b).is_empty());
    }

    #[test]
    fn network_and_identity_checks() {
        assert!(check_ic_url("https://icp0.io").is_ok());
        assert!(check_ic_url("https://icp0.io/").is_ok());
        assert!(check_ic_url("http://127.0.0.1:4943").is_err());
        assert!(check_ic_url("https://evil.example").is_err());
        let mut b = test_manifest().body;
        b.network.name = "local".into();
        assert!(!check_invariants(&b).is_empty());
        let mut b = test_manifest().body;
        b.network.ic_url = "http://localhost:8000".into();
        assert!(!check_invariants(&b).is_empty());

        assert!(check_identity(&Principal::from_text(AUTHORIZED_CALLER).unwrap()).is_ok());
        assert!(check_identity(&Principal::anonymous()).is_err());
        assert!(check_identity(&Principal::from_text(DESTINATION_PRINCIPAL).unwrap()).is_err());
    }

    #[test]
    fn freshness_is_enforced() {
        let b = test_manifest().body; // observed at 1_000_000
        assert!(check_freshness(&b, 1_000_000 + 3_600, 3_600).is_ok());
        assert!(check_freshness(&b, 1_000_000 + 3_601, 3_600).is_err());
        assert!(check_freshness(&b, 1_000_000 - 301, 3_600).is_err());
    }

    #[test]
    fn install_stage_requires_empty_canister_and_unchanged_state() {
        let b = test_manifest().body;
        assert_eq!(
            check_live(&b, Stage::Install, &live_empty(), true),
            Vec::<String>::new()
        );

        let mut l = live_empty();
        l.module_hash = Some("cc".repeat(32));
        let p = check_live(&b, Stage::Install, &l, true);
        assert!(
            p.iter().any(|m| m.contains("UNEXPECTED MODULE HASH")),
            "{p:?}"
        );

        let mut l = live_empty();
        l.controllers.push("zzzzz".into());
        assert!(check_live(&b, Stage::Install, &l, true)
            .iter()
            .any(|m| m.contains("controllers changed")));
        let mut l = live_empty();
        l.controllers.retain(|c| c != AUTHORIZED_CALLER);
        assert!(!check_live(&b, Stage::Install, &l, true).is_empty());

        let mut l = live_empty();
        l.running = Some(false);
        assert!(!check_live(&b, Stage::Install, &l, true).is_empty());
        let mut l = live_empty();
        l.settings_sha256 = Some("dd".repeat(32));
        assert!(!check_live(&b, Stage::Install, &l, true).is_empty());
        let mut l = live_empty();
        l.cycles = Some(5);
        assert!(!check_live(&b, Stage::Install, &l, true).is_empty());
        let mut l = live_empty();
        l.ledger_fee_e8s = 20_000;
        assert!(!check_live(&b, Stage::Install, &l, true).is_empty());
        // Balance drift on either side
        let mut l = live_empty();
        l.source_balance_e8s += 1;
        assert!(check_live(&b, Stage::Install, &l, true)
            .iter()
            .any(|m| m.contains("source balance")));
        let mut l = live_empty();
        l.destination_balance_e8s -= 1;
        assert!(check_live(&b, Stage::Install, &l, true)
            .iter()
            .any(|m| m.contains("destination balance")));
        // Missing status data is a problem when required, tolerated for partial verification.
        let mut l = live_empty();
        l.running = None;
        l.cycles = None;
        l.settings_sha256 = None;
        assert!(!check_live(&b, Stage::Install, &l, true).is_empty());
        assert!(check_live(&b, Stage::Install, &l, false).is_empty());
    }

    #[test]
    fn transfer_stage_requires_the_recovery_wasm_and_the_next_operation() {
        let b = test_manifest().body;
        assert_eq!(
            check_live(&b, Stage::Transfer, &installed_live(1, vec![]), true),
            Vec::<String>::new()
        );
        // Wrong module.
        let mut l = installed_live(1, vec![]);
        l.module_hash = Some("cc".repeat(32));
        assert!(check_live(&b, Stage::Transfer, &l, true)
            .iter()
            .any(|m| m.contains("UNEXPECTED MODULE HASH")));
        // Not installed.
        assert!(!check_live(&b, Stage::Transfer, &live_empty(), true).is_empty());
        // Replay: operation already recorded.
        let l = installed_live(2, vec![completed_op(1, TEST_TRANSFER_E8S)]);
        assert!(check_live(&b, Stage::Transfer, &l, true)
            .iter()
            .any(|m| m.contains("next operation id")));
        // In-doubt operation blocks.
        let mut op = completed_op(1, 1);
        op.status = Status::InDoubt {
            last_error: "x".into(),
        };
        assert!(
            check_live(&b, Stage::Transfer, &installed_live(1, vec![op]), true)
                .iter()
                .any(|m| m.contains("IN DOUBT"))
        );
        // Config mismatch.
        let mut l = installed_live(1, vec![]);
        l.canister_config.as_mut().unwrap().destination = Principal::anonymous();
        assert!(!check_live(&b, Stage::Transfer, &l, true).is_empty());
    }

    #[test]
    fn final_transfer_needs_a_completed_test_transfer() {
        let mut live = installed_live(2, vec![completed_op(1, TEST_TRANSFER_E8S)]);
        live.source_balance_e8s = 94_233_666_604 - 10_010_000;
        live.destination_balance_e8s = 60_000_000;
        let m = build(PrepareInput {
            kind: Kind::Final,
            ic_url: "https://icp0.io",
            now_unix: 1,
            utc: "x".into(),
            live: &live,
            wasm_sha256: WASM.into(),
            wasm_size: 1,
            operation_id: 2,
        })
        .unwrap();
        assert_eq!(
            check_live(&m.body, Stage::Transfer, &live, true),
            Vec::<String>::new()
        );
        let mut no_test = live.clone();
        no_test.canister_state.as_mut().unwrap().operations.clear();
        assert!(check_live(&m.body, Stage::Transfer, &no_test, true)
            .iter()
            .any(|p| p.contains("no completed test transfer")));
    }

    #[test]
    fn transfer_request_pins_operation_amount_fee_and_manifest_tag() {
        let m = test_manifest();
        let r = m.transfer_request().unwrap();
        assert_eq!(r.expected_operation_id, 1);
        assert_eq!(r.amount_e8s, 10_000_000);
        assert_eq!(r.expected_fee_e8s, 10_000);
        assert_eq!(hex(&r.manifest_tag), m.manifest_sha256[..32]);
    }

    #[test]
    fn insufficient_balance_cannot_be_prepared() {
        let mut live = live_empty();
        live.source_balance_e8s = 5_000_000;
        let r = build(PrepareInput {
            kind: Kind::Test,
            ic_url: "https://icp0.io",
            now_unix: 1,
            utc: "x".into(),
            live: &live,
            wasm_sha256: WASM.into(),
            wasm_size: 1,
            operation_id: 1,
        });
        assert!(r.is_err());
        live.source_balance_e8s = 5_000;
        assert!(build(PrepareInput {
            kind: Kind::Final,
            ic_url: "https://icp0.io",
            now_unix: 1,
            utc: "x".into(),
            live: &live,
            wasm_sha256: WASM.into(),
            wasm_size: 1,
            operation_id: 2,
        })
        .is_err());
    }

    // ---- reconciliation ----

    fn rec(
        op: Option<&Operation>,
        next: u64,
        s: u64,
        d: u64,
        blk: BlockEvidence,
    ) -> Reconciliation {
        reconcile(&test_manifest().body, next, op, s, d, &blk)
    }
    const S0: u64 = 94_233_666_604;
    const D0: u64 = 50_000_000;
    const S1: u64 = 94_233_666_604 - 10_010_000;
    const D1: u64 = 60_000_000;

    #[test]
    fn reconciles_a_successful_test_transfer() {
        let op = completed_op(1, TEST_TRANSFER_E8S);
        let r = rec(Some(&op), 2, S1, D1, BlockEvidence::Verified);
        assert_eq!(r.verdict, Verdict::Reconciled);
        assert_eq!(r.source_delta_e8s, -10_010_000);
        assert_eq!(r.destination_delta_e8s, 10_000_000);
    }

    #[test]
    fn reconciliation_flags_every_inconsistency() {
        let op = completed_op(1, TEST_TRANSFER_E8S);
        // Block unverified or mismatched.
        assert_eq!(
            rec(Some(&op), 2, S1, D1, BlockEvidence::Unavailable("x".into())).verdict,
            Verdict::Unverified
        );
        assert_eq!(
            rec(Some(&op), 2, S1, D1, BlockEvidence::Mismatch("x".into())).verdict,
            Verdict::Discrepancy
        );
        // Balances off by one e8s on either side.
        assert_eq!(
            rec(Some(&op), 2, S1 - 1, D1, BlockEvidence::Verified).verdict,
            Verdict::Discrepancy
        );
        assert_eq!(
            rec(Some(&op), 2, S1, D1 + 1, BlockEvidence::Verified).verdict,
            Verdict::Discrepancy
        );
        // Recorded amount differs from the manifest.
        let other = completed_op(1, 5);
        assert_eq!(
            rec(Some(&other), 2, S1, D1, BlockEvidence::Verified).verdict,
            Verdict::Discrepancy
        );
        // Recorded as completed but nothing moved.
        assert_eq!(
            rec(Some(&op), 2, S0, D0, BlockEvidence::Verified).verdict,
            Verdict::Discrepancy
        );
    }

    #[test]
    fn reconciliation_not_submitted_failed_abandoned_and_in_doubt() {
        assert_eq!(
            rec(None, 1, S0, D0, BlockEvidence::NotChecked).verdict,
            Verdict::NotSubmitted
        );
        assert_eq!(
            rec(None, 1, S1, D1, BlockEvidence::NotChecked).verdict,
            Verdict::Discrepancy
        );
        assert_eq!(
            rec(None, 2, S0, D0, BlockEvidence::NotChecked).verdict,
            Verdict::Discrepancy
        );

        let mut op = completed_op(1, TEST_TRANSFER_E8S);
        op.status = Status::Failed { reason: "x".into() };
        assert_eq!(
            rec(Some(&op), 2, S0, D0, BlockEvidence::NotChecked).verdict,
            Verdict::NoFundsMoved
        );
        assert_eq!(
            rec(Some(&op), 2, S1, D1, BlockEvidence::NotChecked).verdict,
            Verdict::Discrepancy
        );
        op.status = Status::Abandoned;
        assert_eq!(
            rec(Some(&op), 2, S0, D0, BlockEvidence::NotChecked).verdict,
            Verdict::NoFundsMoved
        );

        op.status = Status::InDoubt {
            last_error: "x".into(),
        };
        let r = rec(Some(&op), 2, S1, D1, BlockEvidence::NotChecked);
        assert_eq!(r.verdict, Verdict::InDoubt);
        assert!(r.notes.iter().any(|n| n.contains("EXECUTED")));
        let r = rec(Some(&op), 2, S0, D0, BlockEvidence::NotChecked);
        assert_eq!(r.verdict, Verdict::InDoubt);
        assert!(r.notes.iter().any(|n| n.contains("NOT executed")));
    }
}
