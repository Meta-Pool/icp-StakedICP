//! Explicitly authorized recovery test: ONE `Disburse` of a dissolved neuron to the stICP
//! caller-supplied destination's default ICP Ledger account (no built-in default destination).
//!
//! Safety model:
//! * default mode is PREPARE: anonymous, read-only queries only; nothing is signed or sent;
//! * EXECUTE needs `--execute` AND `--approve-payload-sha256 <hash of the exact payload>`, so the
//!   approval covers the neuron, amount and destination shown by PREPARE;
//! * the signer accepts exactly that one payload and nothing else (see `signer.rs`);
//! * no retry, no second neuron, no other command.

use crate::governance::{fmt_e8s, fmt_utc, NeuronId, NeuronInfo};
use crate::snapshot::{self, Snapshot, Status};
use crate::{session, DEFAULT_GOVERNANCE, DEFAULT_IC_URL, DEFAULT_OWNER, DEFAULT_SIGNING};
use anyhow::{anyhow, bail, Context, Result};
use candid::{CandidType, Deserialize, IDLArgs, IDLValue, Principal};
use clap::Args;
use ic_agent::Agent;
use sha2::{Digest, Sha224, Sha256};
use std::{fs::OpenOptions, io::Write, path::PathBuf, time::Duration};

pub const LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
pub const LEDGER_FEE_E8S: u64 = 10_000;
/// `NeuronInfo.state` value for DISSOLVED.
const STATE_DISSOLVED: i32 = 3;
const ABSOLUTE_MAX_SIGNATURES: i64 = 30;

#[derive(Args)]
pub struct DisburseArgs {
    /// Neuron to disburse (default: smallest positive-stake dissolved `info_only` neuron of the baseline)
    #[arg(long)]
    pub neuron_id: Option<u64>,
    /// Amount to disburse, in e8s (required; no default)
    #[arg(long)]
    pub amount_e8s: u64,
    /// Submit the transaction. Requires --approve-payload-sha256 and --owner-pem.
    #[arg(long)]
    pub execute: bool,
    /// SHA-256 of the exact Candid payload, as printed by the prepare step
    #[arg(long)]
    pub approve_payload_sha256: Option<String>,
    /// Hard cap on ECDSA signatures (1 for the call + status polling)
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(2..=ABSOLUTE_MAX_SIGNATURES))]
    pub max_signatures: u32,
    /// PEM of the local owner identity (execute only); `-` reads stdin
    #[arg(long)]
    pub owner_pem: Option<PathBuf>,
    #[arg(long, default_value = "audit-out")]
    pub out_dir: PathBuf,
    /// Principal that receives the ICP (its default-subaccount ICP Ledger account). Required: there is no default.
    #[arg(long)]
    pub destination: String,
    #[arg(long, default_value = LEDGER)]
    pub ledger: String,
    #[arg(long, default_value = DEFAULT_SIGNING)]
    pub signing: String,
    #[arg(long, default_value = DEFAULT_GOVERNANCE)]
    pub governance: String,
    #[arg(long, default_value = DEFAULT_OWNER)]
    pub owner_principal: String,
    #[arg(long, default_value = crate::identity::HISTORICAL_ORACLE_PRINCIPAL)]
    pub expected: String,
    #[arg(long, default_value = DEFAULT_IC_URL)]
    pub ic_url: String,
}

// ---------- ICP Ledger account identifiers ----------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// `crc32(h) || h` with `h = SHA-224("\x0Aaccount-id" || principal || subaccount)`.
pub fn account_id(owner: &Principal, subaccount: Option<[u8; 32]>) -> [u8; 32] {
    let mut h = Sha224::new();
    h.update(b"\x0Aaccount-id");
    h.update(owner.as_slice());
    h.update(subaccount.unwrap_or([0u8; 32]));
    let hash = h.finalize();
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&crc32(&hash).to_be_bytes());
    out[4..].copy_from_slice(&hash);
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------- manage_neuron(Disburse) payload ----------

#[derive(CandidType)]
struct AccountIdentifier {
    hash: Vec<u8>,
}

#[derive(CandidType)]
struct Amount {
    e8s: u64,
}

#[derive(CandidType)]
struct Disburse {
    to_account: Option<AccountIdentifier>,
    amount: Option<Amount>,
}

/// Encoding-only subset of Governance's `Command`: this tool can only ever build a `Disburse`.
#[derive(CandidType)]
enum Command {
    Disburse(Disburse),
}

#[derive(CandidType)]
enum NeuronIdOrSubaccount {
    NeuronId(NeuronId),
}

#[derive(CandidType)]
struct ManageNeuron {
    id: Option<NeuronId>,
    command: Option<Command>,
    neuron_id_or_subaccount: Option<NeuronIdOrSubaccount>,
}

pub fn encode_disburse(
    neuron_id: u64,
    to: &[u8; 32],
    amount_e8s: u64,
) -> Result<Vec<u8>, candid::Error> {
    candid::encode_one(ManageNeuron {
        id: None,
        command: Some(Command::Disburse(Disburse {
            to_account: Some(AccountIdentifier { hash: to.to_vec() }),
            amount: Some(Amount { e8s: amount_e8s }),
        })),
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: neuron_id })),
    })
}

/// Human-readable echo decoded from the actual payload bytes (not from the inputs), failing
/// unless the payload is exactly one `Disburse` command.
pub fn payload_text(bytes: &[u8]) -> Result<String> {
    let args = IDLArgs::from_bytes(bytes)?;
    let top = args.args.first().ok_or_else(|| anyhow!("empty payload"))?;
    let (tag, d) = field(top, "command")
        .and_then(unopt)
        .and_then(variant)
        .ok_or_else(|| anyhow!("payload has no command"))?;
    if tag != candid::idl_hash("Disburse") {
        bail!("payload command is not Disburse");
    }
    let nid = field(top, "neuron_id_or_subaccount")
        .and_then(unopt)
        .and_then(variant)
        .and_then(|(_, v)| field(v, "id"))
        .and_then(as_u64)
        .ok_or_else(|| anyhow!("payload has no neuron id"))?;
    let dest = field(d, "to_account")
        .and_then(unopt)
        .and_then(|a| field(a, "hash"))
        .and_then(as_bytes)
        .ok_or_else(|| anyhow!("payload has no destination"))?;
    let amount = field(d, "amount")
        .and_then(unopt)
        .and_then(|a| field(a, "e8s"))
        .and_then(as_u64)
        .ok_or_else(|| anyhow!("payload has no amount"))?;
    Ok(format!(
        "manage_neuron {{ neuron_id_or_subaccount = NeuronId {{ id = {nid} }}; command = Disburse {{ to_account = {}; amount = {amount} e8s }} }}",
        hex(&dest)
    ))
}

pub fn payload_sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

// ---------- generic Candid inspection (robust to unknown variants) ----------

pub(crate) fn field<'a>(v: &'a IDLValue, name: &str) -> Option<&'a IDLValue> {
    match v {
        IDLValue::Record(fs) => fs
            .iter()
            .find(|f| f.id.get_id() == candid::idl_hash(name))
            .map(|f| &f.val),
        _ => None,
    }
}

pub(crate) fn unopt(v: &IDLValue) -> Option<&IDLValue> {
    match v {
        IDLValue::Opt(b) => Some(&**b),
        _ => None,
    }
}

fn as_u64(v: &IDLValue) -> Option<u64> {
    match v {
        IDLValue::Nat64(n) => Some(*n),
        IDLValue::Nat(n) => n.0.to_string().parse().ok(),
        _ => None,
    }
}

pub(crate) fn as_bytes(v: &IDLValue) -> Option<Vec<u8>> {
    match v {
        IDLValue::Blob(b) => Some(b.clone()),
        IDLValue::Vec(items) => items
            .iter()
            .map(|i| {
                if let IDLValue::Nat8(n) = i {
                    Some(*n)
                } else {
                    None
                }
            })
            .collect(),
        _ => None,
    }
}

fn variant(v: &IDLValue) -> Option<(u32, &IDLValue)> {
    match v {
        IDLValue::Variant(vv) => Some((vv.0.id.get_id(), &vv.0.val)),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum GovernanceOutcome {
    Disbursed { transfer_block_height: u64 },
    Error { error_type: i32, message: String },
    Other(String),
}

pub fn parse_manage_neuron_response(bytes: &[u8]) -> Result<GovernanceOutcome> {
    let args = IDLArgs::from_bytes(bytes)?;
    let top = args.args.first().ok_or_else(|| anyhow!("empty response"))?;
    let Some(cmd) = field(top, "command").and_then(unopt) else {
        return Ok(GovernanceOutcome::Other(args.to_string()));
    };
    let Some((tag, val)) = variant(cmd) else {
        return Ok(GovernanceOutcome::Other(args.to_string()));
    };
    if tag == candid::idl_hash("Disburse") {
        let h = field(val, "transfer_block_height")
            .and_then(as_u64)
            .ok_or_else(|| anyhow!("no transfer_block_height"))?;
        return Ok(GovernanceOutcome::Disbursed {
            transfer_block_height: h,
        });
    }
    if tag == candid::idl_hash("Error") {
        let message = match field(val, "error_message") {
            Some(IDLValue::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let error_type = match field(val, "error_type") {
            Some(IDLValue::Int32(n)) => *n,
            _ => -1,
        };
        return Ok(GovernanceOutcome::Error {
            error_type,
            message,
        });
    }
    Ok(GovernanceOutcome::Other(args.to_string()))
}

pub fn error_type_name(t: i32) -> &'static str {
    match t {
        1 => "Ok",
        2 => "Unavailable",
        3 => "NotAuthorized",
        4 => "NotFound",
        5 => "InvalidCommand",
        6 => "RequiresNotDissolving",
        7 => "RequiresDissolving",
        8 => "RequiresDissolved",
        9 => "HotKey",
        10 => "ResourceExhausted",
        11 => "PreconditionFailed",
        12 => "External",
        13 => "LedgerUpdateOngoing",
        14 => "InsufficientFunds",
        15 => "InvalidPrincipal",
        _ => "other/unspecified",
    }
}

/// What a Governance outcome does and does not prove about the Oracle identity.
pub fn interpret(o: &GovernanceOutcome) -> String {
    match o {
        GovernanceOutcome::Disbursed { .. } => "Governance accepted a signed Disburse from the Oracle principal: the Oracle IS the controller of this neuron (Disburse is controller-only; hotkeys are rejected). ICP left the neuron to the destination account.".into(),
        GovernanceOutcome::Error { error_type: 3, .. } | GovernanceOutcome::Error { error_type: 9, .. } => "NotAuthorized/HotKey: Governance authenticated the Oracle principal (the signature was valid) but it is NOT the controller of this neuron. This proves nothing about who the controller is, and says nothing about the other neurons.".into(),
        GovernanceOutcome::Error { error_type: 4, .. } => "NotFound: Governance does not know this neuron ID; nothing is proven about authority.".into(),
        GovernanceOutcome::Error { .. } => "Governance rejected the command for a reason other than authorization (see error_type/message). Authority is NOT established by this result; fix the cause only with explicit approval.".into(),
        GovernanceOutcome::Other(_) => "Unrecognized response shape; inspect the raw response. Do not retry.".into(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LedgerTransfer {
    pub from_hex: String,
    pub to_hex: String,
    pub amount_e8s: u64,
    pub fee_e8s: u64,
}

pub enum BlockLookup {
    Found(LedgerTransfer),
    Archived,
    Missing(String),
}

pub fn parse_query_blocks(bytes: &[u8]) -> Result<BlockLookup> {
    let args = IDLArgs::from_bytes(bytes)?;
    let top = args.args.first().ok_or_else(|| anyhow!("empty response"))?;
    let blocks = match field(top, "blocks") {
        Some(IDLValue::Vec(b)) => b,
        _ => bail!("no blocks field"),
    };
    let Some(block) = blocks.first() else {
        return Ok(match field(top, "archived_blocks") {
            Some(IDLValue::Vec(a)) if !a.is_empty() => BlockLookup::Archived,
            _ => BlockLookup::Missing("ledger returned no block at that index".into()),
        });
    };
    let op = field(block, "transaction")
        .and_then(|t| field(t, "operation"))
        .and_then(unopt);
    let Some((tag, t)) = op.and_then(variant) else {
        return Ok(BlockLookup::Missing("block has no operation".into()));
    };
    if tag != candid::idl_hash("Transfer") {
        return Ok(BlockLookup::Missing(
            "block operation is not a Transfer".into(),
        ));
    }
    let get = |n: &str| field(t, n);
    let e8s = |n: &str| get(n).and_then(|v| field(v, "e8s")).and_then(as_u64);
    let from: Option<Vec<u8>> = get("from").and_then(as_bytes);
    let to: Option<Vec<u8>> = get("to").and_then(as_bytes);
    match (from, to, e8s("amount"), e8s("fee")) {
        (Some(f), Some(t), Some(a), Some(fee)) => Ok(BlockLookup::Found(LedgerTransfer {
            from_hex: hex(&f),
            to_hex: hex(&t),
            amount_e8s: a,
            fee_e8s: fee,
        })),
        _ => Ok(BlockLookup::Missing(
            "could not read Transfer fields".into(),
        )),
    }
}

// ---------- candidate selection ----------

/// Smallest positive-stake neuron that the baseline saw as `info_only` and DISSOLVED.
pub fn select_smallest_dissolved(s: &Snapshot) -> Option<(u64, u64)> {
    s.neurons
        .iter()
        .filter(|r| r.status == Status::InfoOnly && r.info_state == Some(STATE_DISSOLVED))
        .filter_map(|r| Some((r.info_stake_e8s.filter(|x| *x > 0)?, r.id()?)))
        .min()
        .map(|(stake, id)| (id, stake))
}

// ---------- mainnet reads (anonymous, free) ----------

#[derive(CandidType, Deserialize)]
enum InfoResult {
    Ok(NeuronInfo),
    Err(crate::governance::GovernanceError),
}

async fn neuron_info(agent: &Agent, gov: &Principal, id: u64) -> Result<NeuronInfo> {
    let bytes = agent
        .query(gov, "get_neuron_info")
        .with_arg(candid::encode_one(id)?)
        .call()
        .await
        .context("Governance.get_neuron_info failed")?;
    match candid::decode_one::<InfoResult>(&bytes)? {
        InfoResult::Ok(i) => Ok(i),
        InfoResult::Err(e) => bail!(
            "Governance.get_neuron_info error {}: {}",
            e.error_type,
            e.error_message
        ),
    }
}

#[derive(CandidType)]
struct BalanceArgs {
    account: String,
}

#[derive(CandidType, Deserialize)]
struct Tokens {
    e8s: u64,
}

pub(crate) async fn ledger_balance(agent: &Agent, ledger: &Principal, account_hex: &str) -> Result<u64> {
    let bytes = agent
        .query(ledger, "account_balance_dfx")
        .with_arg(candid::encode_one(BalanceArgs {
            account: account_hex.to_string(),
        })?)
        .call()
        .await
        .context("Ledger.account_balance_dfx failed")?;
    Ok(candid::decode_one::<Tokens>(&bytes)?.e8s)
}

pub(crate) async fn ledger_block(agent: &Agent, ledger: &Principal, height: u64) -> Result<BlockLookup> {
    #[derive(CandidType)]
    struct Args {
        start: u64,
        length: u64,
    }
    let bytes = agent
        .query(ledger, "query_blocks")
        .with_arg(candid::encode_one(Args {
            start: height,
            length: 1,
        })?)
        .call()
        .await
        .context("Ledger.query_blocks failed")?;
    parse_query_blocks(&bytes)
}

struct Snapshot0 {
    info: NeuronInfo,
    dest_balance: u64,
}

async fn read_state(
    agent: &Agent,
    gov: &Principal,
    ledger: &Principal,
    id: u64,
    dest_hex: &str,
) -> Result<Snapshot0> {
    Ok(Snapshot0 {
        info: neuron_info(agent, gov, id).await?,
        dest_balance: ledger_balance(agent, ledger, dest_hex).await?,
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run(a: DisburseArgs) -> Result<bool> {
    let gov = Principal::from_text(&a.governance).context("invalid --governance")?;
    let ledger = Principal::from_text(&a.ledger).context("invalid --ledger")?;
    let destination = Principal::from_text(&a.destination).context("invalid --destination")?;
    let signing = Principal::from_text(&a.signing).context("invalid --signing")?;
    let owner_principal =
        Principal::from_text(&a.owner_principal).context("invalid --owner-principal")?;
    let expected = Principal::from_text(&a.expected).context("invalid --expected")?;

    let (neuron_id, baseline_note) = match a.neuron_id {
        Some(id) => (id, "given on the command line".to_string()),
        None => {
            let all = snapshot::load_snapshots(&a.out_dir)?;
            let (path, snap) = all
                .last()
                .ok_or_else(|| anyhow!("no baseline snapshot in {}", a.out_dir.display()))?;
            let (id, stake) = select_smallest_dissolved(snap).ok_or_else(|| {
                anyhow!("baseline has no dissolved info_only neuron with positive stake")
            })?;
            (
                id,
                format!(
                    "smallest positive-stake dissolved info_only neuron in {} ({} ICP)",
                    path.display(),
                    fmt_e8s(stake.into())
                ),
            )
        }
    };

    let dest = account_id(&destination, None);
    let dest_hex = hex(&dest);
    let anon = Agent::builder().with_url(a.ic_url.clone()).build()?;
    let before = read_state(&anon, &gov, &ledger, neuron_id, &dest_hex).await?;

    let payload = encode_disburse(neuron_id, &dest, a.amount_e8s)?;
    let sha = payload_sha256(&payload);
    let i = &before.info;

    println!("=== Recovery test: single Disburse (NOT executed unless --execute is approved) ===");
    println!("Neuron ID        : {neuron_id}  [{baseline_note}]");
    println!("Live state       : {} (state={}), dissolve delay {}s, stake (net of fees) {} ICP, voting power {}",
        crate::governance::state_name(i.state), i.state, i.dissolve_delay_seconds, fmt_e8s(i.stake_e8s.into()), i.voting_power);
    println!("Destination      : ICP Ledger account {dest_hex}");
    println!("  derived from   : principal {destination} + default subaccount (same derivation as `dfx ledger account-id --of-principal`)");
    println!(
        "  live balance   : {} ICP ({} e8s) on ledger {ledger}",
        fmt_e8s(before.dest_balance.into()),
        before.dest_balance
    );
    println!(
        "Amount requested : {} ICP ({} e8s); remainder stays in the neuron",
        fmt_e8s(a.amount_e8s.into()),
        a.amount_e8s
    );
    println!("Ledger fee       : {} e8s ({} ICP); the neuron's ledger account pays it. Exact split is shown by the ledger block after execution.", LEDGER_FEE_E8S, fmt_e8s(LEDGER_FEE_E8S.into()));
    println!("Governance call  : update {gov}.manage_neuron");
    println!("Payload (candid) : {}", payload_text(&payload)?);
    println!("Payload (hex)    : {}", hex(&payload));
    println!("Payload SHA-256  : {sha}");
    println!("Max signing cost : {} signatures = {} cycles charged to the signing canister (no ICP cost besides the ledger fee)",
        a.max_signatures, u64::from(a.max_signatures) * crate::audit::CYCLES_PER_SIGNATURE);

    println!("Expected on success: destination +{} e8s; neuron net stake -{} e8s (or -{} e8s if the fee is deducted from the stake); one Transfer block of exactly {} e8s, fee {} e8s",
        a.amount_e8s, a.amount_e8s, a.amount_e8s + LEDGER_FEE_E8S, a.amount_e8s, LEDGER_FEE_E8S);
    match prior_attempt(&a.out_dir, neuron_id) {
        Some(p) => println!("Prior attempts   : RECORDED at {}", p.display()),
        None => println!("Prior attempts   : none recorded"),
    }
    println!();
    println!("--- Independent verification: run these BEFORE executing and keep the output ---");
    println!("{}", verify_commands(neuron_id, &dest_hex, None));

    let mut problems = vec![];
    if let Some(p) = prior_attempt(&a.out_dir, neuron_id) {
        problems.push(format!(
            "a disbursement attempt for this neuron is already recorded ({}); refusing. Review it; only delete it deliberately",
            p.display()
        ));
    }
    if i.state != STATE_DISSOLVED {
        problems.push(format!("neuron is not DISSOLVED (state {})", i.state));
    }
    if a.amount_e8s <= LEDGER_FEE_E8S {
        problems.push("amount must exceed the ledger fee".to_string());
    }
    if i.stake_e8s < a.amount_e8s.saturating_add(LEDGER_FEE_E8S) {
        problems.push(format!(
            "neuron stake {} e8s is below amount + fee",
            i.stake_e8s
        ));
    }
    if before.dest_balance == 0 {
        println!("WARNING          : destination account currently holds 0 ICP; confirm the principal and account id with the recipient before approving");
    }
    if !problems.is_empty() {
        for p in &problems {
            println!("BLOCKED          : {p}");
        }
        bail!("pre-execution checks failed; nothing was sent");
    }

    if !a.execute {
        println!();
        println!("PREPARE ONLY: nothing signed, nothing sent. To approve exactly this payload, re-run with:");
        println!("  --execute --approve-payload-sha256 {sha} --owner-pem -");
        return Ok(true);
    }

    match a.approve_payload_sha256.as_deref() {
        Some(h) if h.eq_ignore_ascii_case(&sha) => {}
        Some(_) => {
            bail!("--approve-payload-sha256 does not match the payload above; refusing to sign")
        }
        None => bail!("--execute requires --approve-payload-sha256 {sha}"),
    }
    let pem = a
        .owner_pem
        .as_ref()
        .ok_or_else(|| anyhow!("--execute requires --owner-pem"))?;

    let pre = session::preflight(pem, owner_principal, signing, &a.ic_url).await?;
    std::fs::create_dir_all(a.out_dir.join("recovery"))?;
    let s = session::connect_oracle_with(
        pre,
        signing,
        gov,
        expected,
        &a.ic_url,
        a.max_signatures,
        Some(payload.clone()),
    )
    .await?;

    let intent = serde_json::json!({
        "status": "submitting",
        "recorded_at_unix": now_unix(),
        "neuron_id": neuron_id.to_string(),
        "oracle_principal": s.principal.to_text(),
        "destination_account_hex": dest_hex,
        "amount_requested_e8s": a.amount_e8s,
        "payload_hex": hex(&payload),
        "payload_sha256": sha,
        "before": { "neuron_stake_e8s": before.info.stake_e8s, "destination_balance_e8s": before.dest_balance },
        "note": "Written immediately before signing. Its existence blocks any second execution for this neuron.",
    });
    let lock = write_lock(&a.out_dir, neuron_id, &intent)?;
    println!(
        "\nIntent recorded  : {} (any further execution for this neuron is now refused)",
        lock.display()
    );

    println!(
        "SUBMITTING manage_neuron(Disburse) as {} ... (single attempt; this tool never resubmits)",
        s.principal
    );
    let submitted_at = now_unix();
    let result = s
        .agent
        .update(&gov, "manage_neuron")
        .with_arg(payload.clone())
        .call_and_wait()
        .await;
    let used = s.identity.signatures_used().min(a.max_signatures);
    println!("Signatures used  : {used}");

    let mut response_text = String::new();
    let mut transport_error: Option<(&'static str, String)> = None;
    let outcome: Option<GovernanceOutcome> = match &result {
        Ok(bytes) => {
            response_text = IDLArgs::from_bytes(bytes)
                .map(|x| x.to_string())
                .unwrap_or_else(|e| format!("<undecodable: {e}> raw hex {}", hex(bytes)));
            match parse_manage_neuron_response(bytes) {
                Ok(o) => Some(o),
                Err(e) => {
                    response_text.push_str(&format!(" [parse error: {e}]"));
                    None
                }
            }
        }
        Err(e) => {
            transport_error = Some((classify_agent_error(e), e.to_string()));
            None
        }
    };

    println!();
    println!("--- Governance response (NOT yet proof of a ledger transfer) ---");
    if let Some((kind, msg)) = &transport_error {
        println!("No Governance reply was received: {kind}: {msg}");
        println!("This does NOT mean the call failed: the message may still have executed. DO NOT RETRY.");
    } else {
        println!("Raw reply        : {response_text}");
    }
    if let Some(o) = &outcome {
        match o {
            GovernanceOutcome::Disbursed {
                transfer_block_height,
            } => {
                println!(
                    "Governance said  : ACCEPTED, transfer_block_height = {transfer_block_height}"
                )
            }
            GovernanceOutcome::Error {
                error_type,
                message,
            } => {
                println!(
                    "Governance said  : REJECTED, error_type {error_type} ({}) : {message}",
                    error_type_name(*error_type)
                )
            }
            GovernanceOutcome::Other(_) => println!("Governance said  : unrecognized reply shape"),
        }
        println!("Meaning          : {}", interpret(o));
    }

    // Independent evidence, read anonymously from the Ledger and Governance.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let block = match &outcome {
        Some(GovernanceOutcome::Disbursed {
            transfer_block_height,
        }) => Some((
            *transfer_block_height,
            verify_on_ledger(
                &anon,
                &ledger,
                *transfer_block_height,
                &dest_hex,
                a.amount_e8s,
            )
            .await,
        )),
        _ => None,
    };
    let after: Option<Balances> = match read_state(&anon, &gov, &ledger, neuron_id, &dest_hex).await
    {
        Ok(x) => Some(Balances {
            neuron_stake_e8s: x.info.stake_e8s,
            dest_e8s: x.dest_balance,
        }),
        Err(e) => {
            println!("WARNING          : could not re-read balances after execution: {e}");
            None
        }
    };
    let before_b = Balances {
        neuron_stake_e8s: before.info.stake_e8s,
        dest_e8s: before.dest_balance,
    };

    println!();
    println!("--- Ledger evidence (independent of Governance's reply) ---");
    match &block {
        Some((h, BlockCheck::Verified(t))) => {
            println!("Block index      : {h}");
            println!("Transfer         : {} -> {}", t.from_hex, t.to_hex);
            println!(
                "Amount in block  : {} e8s ({} ICP)   requested: {} e8s   => MATCH",
                t.amount_e8s,
                fmt_e8s(t.amount_e8s.into()),
                a.amount_e8s
            );
            println!("Fee in block     : {} e8s ({} ICP)   (paid by the neuron's ledger account on top of the amount)", t.fee_e8s, fmt_e8s(t.fee_e8s.into()));
            println!(
                "Destination      : block recipient == destination account {dest_hex}   => MATCH"
            );
        }
        Some((h, BlockCheck::Mismatch { transfer: t, why })) => {
            println!("Block index      : {h}");
            println!(
                "Block contents   : {} -> {} amount {} e8s fee {} e8s",
                t.from_hex, t.to_hex, t.amount_e8s, t.fee_e8s
            );
            println!("MISMATCH         : {why}");
        }
        Some((h, BlockCheck::Unavailable(why))) => {
            println!("Block index      : {h} (reported by Governance)");
            println!("NOT VERIFIED     : {why}");
        }
        None => println!(
            "No block index was returned by Governance, so there is no ledger transfer to verify."
        ),
    }

    let transfer_ref = match &block {
        Some((_, BlockCheck::Verified(t))) => Some(t),
        _ => None,
    };
    println!();
    println!("--- Reconciliation ---");
    print!(
        "{}",
        reconciliation_table(
            &before_b,
            after.as_ref(),
            a.amount_e8s,
            transfer_ref,
            block.as_ref().map(|(h, _)| *h)
        )
    );
    let notes = expectation_notes(&before_b, after.as_ref(), a.amount_e8s, LEDGER_FEE_E8S);
    for n in &notes {
        println!("  * {n}");
    }

    let verdict = decide(outcome.as_ref(), block.as_ref().map(|(_, c)| c));
    let explanation = verdict_explanation(
        verdict,
        outcome.as_ref(),
        transport_error.as_ref().map(|(k, _)| *k),
    );
    println!();
    println!("================ FINAL VERDICT ================");
    println!("{}", verdict.headline());
    println!("{explanation}");
    if matches!(verdict, Verdict::Pending | Verdict::Unknown) {
        println!("DO NOT RETRY. Re-check with the independent commands below; a re-run of this tool is refused by the intent record.");
    }
    println!("================================================");

    let block_height = block.as_ref().map(|(h, _)| *h);
    let commands = verify_commands(neuron_id, &dest_hex, block_height);
    println!();
    println!("--- Independent verification (run from the repository root) ---");
    println!("{commands}");

    let stamp = crate::governance::fmt_compact_utc(submitted_at);
    let base = a.out_dir.join("recovery").join(format!("disburse-{stamp}"));
    let delta = |b: u64, a_: u64| (i128::from(a_) - i128::from(b)).to_string();
    let report = serde_json::json!({
        "verdict": verdict.headline(),
        "verdict_explanation": explanation,
        "submitted_at_unix": submitted_at,
        "submitted_at_utc": fmt_utc(submitted_at),
        "oracle_principal": s.principal.to_text(),
        "governance": gov.to_text(),
        "neuron_id": neuron_id.to_string(),
        "destination_account_hex": dest_hex,
        "destination_derivation": format!("principal {destination}, default subaccount"),
        "amount_requested_e8s": a.amount_e8s,
        "ledger_fee_e8s": LEDGER_FEE_E8S,
        "payload_hex": hex(&payload),
        "payload_candid": payload_text(&payload)?,
        "payload_sha256": sha,
        "signatures_used": used,
        "transport_error": transport_error.as_ref().map(|(k, m)| serde_json::json!({ "kind": k, "message": m })),
        "governance_response_raw": response_text,
        "governance_outcome": outcome.as_ref().map(|o| format!("{o:?}")),
        "interpretation": outcome.as_ref().map(interpret),
        "ledger_block_index": block_height,
        "ledger_check": block.as_ref().map(|(_, c)| match c {
            BlockCheck::Verified(t) => serde_json::json!({ "result": "verified", "from": t.from_hex, "to": t.to_hex, "amount_e8s": t.amount_e8s, "fee_e8s": t.fee_e8s }),
            BlockCheck::Mismatch { transfer: t, why } => serde_json::json!({ "result": "mismatch", "why": why, "from": t.from_hex, "to": t.to_hex, "amount_e8s": t.amount_e8s, "fee_e8s": t.fee_e8s }),
            BlockCheck::Unavailable(why) => serde_json::json!({ "result": "unavailable", "why": why }),
        }),
        "before": { "neuron_stake_e8s": before_b.neuron_stake_e8s, "destination_balance_e8s": before_b.dest_e8s },
        "after": after.as_ref().map(|x| serde_json::json!({ "neuron_stake_e8s": x.neuron_stake_e8s, "destination_balance_e8s": x.dest_e8s })),
        "destination_delta_e8s": after.as_ref().map(|x| delta(before_b.dest_e8s, x.dest_e8s)),
        "neuron_stake_delta_e8s": after.as_ref().map(|x| delta(before_b.neuron_stake_e8s, x.neuron_stake_e8s)),
        "reconciliation_notes": notes,
        "independent_verification_commands": commands,
        "intent_record": lock.display().to_string(),
    });
    let md = markdown(
        &report,
        &reconciliation_table(
            &before_b,
            after.as_ref(),
            a.amount_e8s,
            transfer_ref,
            block_height,
        ),
        &notes,
    );
    for (ext, body) in [
        ("json", serde_json::to_vec_pretty(&report)?),
        ("md", md.into_bytes()),
    ] {
        let path = base.with_extension(ext);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        f.write_all(&body)?;
        println!("Report           : {}", path.display());
    }
    Ok(verdict == Verdict::Success)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Success,
    RejectedNotAuthorized,
    FailedGovernanceError,
    Pending,
    Unknown,
}

impl Verdict {
    pub fn headline(&self) -> &'static str {
        match self {
            Self::Success => "SUCCESS — LEDGER TRANSFER VERIFIED",
            Self::RejectedNotAuthorized => "REJECTED — NOT AUTHORIZED",
            Self::FailedGovernanceError => "FAILED — GOVERNANCE ERROR",
            Self::Pending => "PENDING — GOVERNANCE ACCEPTED, LEDGER NOT YET VERIFIED",
            Self::Unknown => "UNKNOWN — TRANSACTION OUTCOME COULD NOT BE DETERMINED",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockCheck {
    /// The block is a Transfer to the expected account for exactly the requested amount.
    Verified(LedgerTransfer),
    Mismatch {
        transfer: LedgerTransfer,
        why: String,
    },
    Unavailable(String),
}

pub fn check_block(
    lookup: Result<BlockLookup, String>,
    dest_hex: &str,
    amount_e8s: u64,
) -> BlockCheck {
    match lookup {
        Ok(BlockLookup::Found(t)) => {
            let mut why = vec![];
            if t.to_hex != dest_hex {
                why.push(format!(
                    "recipient {} is not the destination account",
                    t.to_hex
                ));
            }
            if t.amount_e8s != amount_e8s {
                why.push(format!(
                    "amount {} e8s != requested {amount_e8s} e8s",
                    t.amount_e8s
                ));
            }
            if why.is_empty() {
                BlockCheck::Verified(t)
            } else {
                BlockCheck::Mismatch {
                    transfer: t,
                    why: why.join("; "),
                }
            }
        }
        Ok(BlockLookup::Archived) => BlockCheck::Unavailable(
            "block is held by an archive canister; use the query_blocks command below".into(),
        ),
        Ok(BlockLookup::Missing(m)) => BlockCheck::Unavailable(m),
        Err(e) => BlockCheck::Unavailable(e),
    }
}

/// Success requires independently verified Ledger evidence; Governance's reply alone never suffices.
pub fn decide(outcome: Option<&GovernanceOutcome>, block: Option<&BlockCheck>) -> Verdict {
    match outcome {
        Some(GovernanceOutcome::Disbursed { .. }) => match block {
            Some(BlockCheck::Verified(_)) => Verdict::Success,
            Some(BlockCheck::Mismatch { .. }) => Verdict::Unknown,
            Some(BlockCheck::Unavailable(_)) | None => Verdict::Pending,
        },
        Some(GovernanceOutcome::Error { error_type: 3, .. })
        | Some(GovernanceOutcome::Error { error_type: 9, .. }) => Verdict::RejectedNotAuthorized,
        Some(GovernanceOutcome::Error { .. }) => Verdict::FailedGovernanceError,
        Some(GovernanceOutcome::Other(_)) | None => Verdict::Unknown,
    }
}

pub fn verdict_explanation(
    v: Verdict,
    o: Option<&GovernanceOutcome>,
    transport_kind: Option<&str>,
) -> String {
    match v {
        Verdict::Success => "Governance accepted the Disburse AND the ICP Ledger block at the returned index is a Transfer of exactly the requested amount to the destination account. The Oracle principal is the controller of this neuron.".into(),
        Verdict::RejectedNotAuthorized => "Governance authenticated the Oracle's signature and refused: the Oracle is not the controller of this neuron (hotkeys cannot disburse). No ICP moved. This proves nothing about who the controller is, nor about other neurons.".into(),
        Verdict::FailedGovernanceError => format!("Governance rejected the command for a non-authorization reason. No ICP moved per Governance. {} Authority is NOT established either way.", o.map(interpret).unwrap_or_default()),
        Verdict::Pending => "Governance replied that the Disburse was accepted, but the Ledger block could not be read yet. Do NOT treat this as success until the block is verified independently (commands below).".into(),
        Verdict::Unknown => match transport_kind {
            Some("TIMEOUT") => "The call timed out while waiting for the reply. A timeout is NOT a failure: the disbursement may have executed. Compare the balances and the ledger independently before doing anything else.".into(),
            Some(k) => format!("No usable Governance reply ({k}). The disbursement may or may not have executed. Compare the balances and the ledger independently before doing anything else."),
            None => "The reply or the ledger evidence was inconsistent or unrecognized (see above). Treat the outcome as undetermined and verify independently.".into(),
        },
    }
}

pub fn classify_agent_error(e: &ic_agent::AgentError) -> &'static str {
    use ic_agent::AgentError as E;
    match e {
        E::TimeoutWaitingForResponse() => "TIMEOUT",
        E::CertifiedReject { .. } | E::UncertifiedReject { .. } => "REPLICA_REJECT",
        _ => "TRANSPORT_OR_OTHER",
    }
}

async fn verify_on_ledger(
    anon: &Agent,
    ledger: &Principal,
    height: u64,
    dest_hex: &str,
    amount: u64,
) -> BlockCheck {
    let mut last = BlockCheck::Unavailable("not attempted".into());
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        last = check_block(
            ledger_block(anon, ledger, height)
                .await
                .map_err(|e| e.to_string()),
            dest_hex,
            amount,
        );
        if !matches!(last, BlockCheck::Unavailable(_)) {
            break;
        }
    }
    last
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balances {
    pub neuron_stake_e8s: u64,
    pub dest_e8s: u64,
}

fn signed_icp(d: i128) -> String {
    format!(
        "{}{} ICP",
        if d < 0 { "-" } else { "+" },
        fmt_e8s(d.unsigned_abs())
    )
}

pub fn reconciliation_table(
    before: &Balances,
    after: Option<&Balances>,
    requested: u64,
    t: Option<&LedgerTransfer>,
    block: Option<u64>,
) -> String {
    let icp = |v: u64| format!("{} ICP", fmt_e8s(v.into()));
    let row = |name: &str, b: u64, a: Option<u64>| match a {
        Some(a) => format!(
            "| {name:<24} | {:>18} | {:>18} | {:>19} |\n",
            icp(b),
            icp(a),
            signed_icp(i128::from(a) - i128::from(b))
        ),
        None => format!(
            "| {name:<24} | {:>18} | {:>18} | {:>19} |\n",
            icp(b),
            "unavailable",
            "unavailable"
        ),
    };
    let mut s = String::new();
    s.push_str("| Metric                   |             Before |              After |               Delta |\n");
    s.push_str("|--------------------------|-------------------:|-------------------:|--------------------:|\n");
    s.push_str(&row(
        "Neuron net stake",
        before.neuron_stake_e8s,
        after.map(|x| x.neuron_stake_e8s),
    ));
    s.push_str(&row(
        "Deposits Ledger balance",
        before.dest_e8s,
        after.map(|x| x.dest_e8s),
    ));
    s.push('\n');
    s.push_str(&format!("Requested amount        : {}\n", icp(requested)));
    match t {
        Some(t) => {
            s.push_str(&format!(
                "Actual transferred      : {} (from the verified ledger block)\n",
                icp(t.amount_e8s)
            ));
            s.push_str(&format!("Transaction fee         : {}\n", icp(t.fee_e8s)));
        }
        None => {
            s.push_str("Actual transferred      : not verified on the ledger\n");
            s.push_str("Transaction fee         : not verified on the ledger\n");
        }
    }
    s.push_str(&format!(
        "Ledger block index      : {}\n",
        block.map_or("none".to_string(), |b| b.to_string())
    ));
    s
}

/// Compares the observed balance changes with what a successful disbursement implies, without assuming.
pub fn expectation_notes(
    before: &Balances,
    after: Option<&Balances>,
    requested: u64,
    fee: u64,
) -> Vec<String> {
    let mut n = vec![
        format!("The ledger fee ({fee} e8s) is charged to the neuron's ledger account on top of the amount; the recipient receives the full amount."),
        "Governance replies after its ledger call completes, so balance changes are normally visible immediately; any lag would make the 'After' column stale, never wrong.".to_string(),
    ];
    let Some(a) = after else {
        n.push("After-state could not be read: no balance conclusion can be drawn. Use the independent commands.".into());
        return n;
    };
    let dd = i128::from(a.dest_e8s) - i128::from(before.dest_e8s);
    let nd = i128::from(a.neuron_stake_e8s) - i128::from(before.neuron_stake_e8s);
    let req = i128::from(requested);
    n.push(if dd == req {
        format!("Deposits balance rose by exactly the requested amount ({requested} e8s): MATCHES expectation.")
    } else if dd == 0 {
        "Deposits balance did NOT change: the transfer did not (yet) land, or something offset it. Do not assume it moved.".into()
    } else {
        format!("Destination balance changed by {dd:+} e8s, not the requested {requested} e8s: MISMATCH. Other deposits or withdrawals on that account in the same window can explain it; rely on the ledger block, not the balance.")
    });
    n.push(if nd == -req {
        "Neuron net stake fell by exactly the requested amount (the fee was not deducted from the cached stake).".into()
    } else if nd == -(req + i128::from(fee)) {
        "Neuron net stake fell by the requested amount plus the ledger fee.".into()
    } else if nd == 0 {
        "Neuron net stake did NOT change: the disbursement did not (yet) take effect, or the stake cache is stale.".into()
    } else {
        format!("Neuron net stake changed by {nd:+} e8s, which is neither -amount nor -(amount+fee): MISMATCH; investigate before any further action.")
    });
    n
}

const GOV_DID: &str = "candid/nns-governance.did";
const LEDGER_DID: &str = "candid/nns-ledger.did";

/// Copy-paste `dfx` commands (anonymous queries, free) for independent verification.
pub fn verify_commands(neuron_id: u64, account_hex: &str, block: Option<u64>) -> String {
    let block_cmd = match block {
        Some(b) => format!("{b} : nat64"),
        None => "<BLOCK_INDEX> : nat64".to_string(),
    };
    format!(
        "# 1+2. Neuron state and stake. PROVES: state = 3 means DISSOLVED; stake_e8s is the net stake.\n\
         dfx canister --network ic --identity anonymous call --query --candid {GOV_DID} {GOVERNANCE} get_neuron_info '({neuron_id} : nat64)'\n\
         \n\
         # 3. Deposits ICP balance. PROVES: e8s is the liquid balance (1 ICP = 100_000_000 e8s).\n\
         dfx canister --network ic --identity anonymous call --query --candid {LEDGER_DID} {LEDGER} account_balance_dfx '(record {{ account = \"{account_hex}\" }})'\n\
         \n\
         # 4. The transfer itself. PROVES movement: blocks[0].transaction.operation = opt variant {{ Transfer = record {{ to = blob \"...\"; amount = record {{ e8s = ... }}; fee = ...; from = ... }} }}\n\
         #    with `to` equal to the bytes of {account_hex} (printed as \\XX hex escapes: \\0c\\5e\\0d\\e7...) and amount = requested e8s.\n\
         #    If `blocks` is empty and `archived_blocks` is non-empty, query the archive callback shown there with get_blocks (same args).\n\
         dfx canister --network ic --identity anonymous call --query --candid {LEDGER_DID} {LEDGER} query_blocks '(record {{ start = {block_cmd}; length = 1 : nat64 }})'\n\
         \n\
         # Human-readable cross-check (no tooling): https://dashboard.internetcomputer.org/account/{account_hex}\n",
        GOVERNANCE = DEFAULT_GOVERNANCE,
    )
}

pub fn lock_path(out_dir: &std::path::Path, neuron_id: u64) -> PathBuf {
    out_dir
        .join("recovery")
        .join(format!("disburse-{neuron_id}.intent.json"))
}

pub fn prior_attempt(out_dir: &std::path::Path, neuron_id: u64) -> Option<PathBuf> {
    Some(lock_path(out_dir, neuron_id)).filter(|p| p.exists())
}

/// Atomically creates the intent record; fails if one already exists (double-submit guard).
pub fn write_lock(
    out_dir: &std::path::Path,
    neuron_id: u64,
    intent: &serde_json::Value,
) -> Result<PathBuf> {
    let path = lock_path(out_dir, neuron_id);
    std::fs::create_dir_all(path.parent().expect("has parent"))?;
    let mut f = OpenOptions::new().write(true).create_new(true).open(&path).with_context(|| {
        format!("a disbursement attempt for neuron {neuron_id} is already recorded at {}; refusing to submit again", path.display())
    })?;
    f.write_all(&serde_json::to_vec_pretty(intent)?)?;
    f.sync_all()?;
    Ok(path)
}

fn markdown(r: &serde_json::Value, table: &str, notes: &[String]) -> String {
    let g = |k: &str| {
        r[k].as_str()
            .map(str::to_string)
            .unwrap_or_else(|| r[k].to_string())
    };
    let notes = notes.iter().map(|n| format!("- {n}\n")).collect::<String>();
    format!(
        "# Disburse recovery test\n\n## Verdict: {}\n\n{}\n\n- Submitted: {}\n- Oracle principal: `{}`\n- Neuron: `{}`\n- Destination account: `{}` ({})\n- Signatures used: {}\n- Intent record: `{}`\n\n## Governance\n\n- Outcome: `{}`\n- Raw response: `{}`\n- Transport error: {}\n- Interpretation: {}\n\n## Ledger\n\n- Check: {}\n\n## Reconciliation\n\n```\n{}```\n\n{}\n## Payload (exact bytes that were signed)\n\n- Candid: `{}`\n- Hex: `{}`\n- SHA-256: `{}`\n\n## Independent verification\n\n```\n{}```\n",
        g("verdict"), g("verdict_explanation"), g("submitted_at_utc"), g("oracle_principal"), g("neuron_id"), g("destination_account_hex"), g("destination_derivation"),
        g("signatures_used"), g("intent_record"),
        g("governance_outcome"), g("governance_response_raw"), g("transport_error"), g("interpretation"),
        g("ledger_check"), table, notes,
        g("payload_candid"), g("payload_hex"), g("payload_sha256"), g("independent_verification_commands"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::tests::{full, snap};
    use crate::snapshot::NeuronRecord;

    fn dissolved_info(id: u64, stake: u64, state: i32) -> NeuronRecord {
        let mut r = NeuronRecord::blank(id, Status::InfoOnly);
        r.info_stake_e8s = Some(stake);
        r.info_state = Some(state);
        r
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn destination_account_id_matches_independent_python_computation() {
        let p = Principal::from_text("hnwvc-lyaaa-aaaal-aaf6q-cai").unwrap();
        assert_eq!(hex(p.as_slice()), "000000000160017d0101");
        assert_eq!(
            hex(&account_id(&p, None)),
            "0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed"
        );
    }

    #[test]
    fn payload_is_a_single_disburse_with_exact_fields() {
        let to = [9u8; 32];
        let bytes = encode_disburse(13_739_920_397_011_050_625, &to, 10_000_000).unwrap();
        let text = payload_text(&bytes).unwrap();
        assert_eq!(
            text,
            format!(
                "manage_neuron {{ neuron_id_or_subaccount = NeuronId {{ id = 13739920397011050625 }}; command = Disburse {{ to_account = {}; amount = 10000000 e8s }} }}",
                "09".repeat(32)
            )
        );
        assert_eq!(
            bytes,
            encode_disburse(13_739_920_397_011_050_625, &to, 10_000_000).unwrap()
        );
        assert_ne!(
            payload_sha256(&bytes),
            payload_sha256(&encode_disburse(13_739_920_397_011_050_625, &to, 10_000_001).unwrap())
        );
        assert_ne!(
            payload_sha256(&bytes),
            payload_sha256(&encode_disburse(13_739_920_397_011_050_626, &to, 10_000_000).unwrap())
        );
        assert_ne!(
            payload_sha256(&bytes),
            payload_sha256(
                &encode_disburse(13_739_920_397_011_050_625, &[8u8; 32], 10_000_000).unwrap()
            )
        );
    }

    #[derive(CandidType)]
    struct GovErr {
        error_message: String,
        error_type: i32,
    }
    #[derive(CandidType)]
    struct DisbResp {
        transfer_block_height: u64,
    }
    #[derive(CandidType)]
    enum Cmd1 {
        Error(GovErr),
        Split(()),
        Disburse(DisbResp),
    }
    #[derive(CandidType)]
    struct Resp {
        command: Option<Cmd1>,
    }

    #[test]
    fn parses_governance_responses() {
        let ok = candid::encode_one(Resp {
            command: Some(Cmd1::Disburse(DisbResp {
                transfer_block_height: 42,
            })),
        })
        .unwrap();
        assert_eq!(
            parse_manage_neuron_response(&ok).unwrap(),
            GovernanceOutcome::Disbursed {
                transfer_block_height: 42
            }
        );
        let err = candid::encode_one(Resp {
            command: Some(Cmd1::Error(GovErr {
                error_message: "nope".into(),
                error_type: 3,
            })),
        })
        .unwrap();
        let o = parse_manage_neuron_response(&err).unwrap();
        assert_eq!(
            o,
            GovernanceOutcome::Error {
                error_type: 3,
                message: "nope".into()
            }
        );
        assert!(interpret(&o).contains("NOT the controller"));
        let other = candid::encode_one(Resp {
            command: Some(Cmd1::Split(())),
        })
        .unwrap();
        assert!(matches!(
            parse_manage_neuron_response(&other).unwrap(),
            GovernanceOutcome::Other(_)
        ));
        let none = candid::encode_one(Resp { command: None }).unwrap();
        assert!(matches!(
            parse_manage_neuron_response(&none).unwrap(),
            GovernanceOutcome::Other(_)
        ));
        assert!(interpret(&GovernanceOutcome::Error {
            error_type: 8,
            message: String::new()
        })
        .contains("NOT established"));
    }

    #[derive(CandidType)]
    struct Tk {
        e8s: u64,
    }
    #[derive(CandidType)]
    enum Op {
        Mint(()),
        Transfer {
            to: Vec<u8>,
            fee: Tk,
            from: Vec<u8>,
            amount: Tk,
        },
    }
    #[derive(CandidType)]
    struct Tx {
        memo: u64,
        operation: Option<Op>,
    }
    #[derive(CandidType)]
    struct Blk {
        transaction: Tx,
        timestamp: u64,
    }
    #[derive(CandidType)]
    struct Qb {
        blocks: Vec<Blk>,
        first_block_index: u64,
    }

    #[test]
    fn parses_ledger_transfer_block() {
        let q = Qb {
            blocks: vec![Blk {
                transaction: Tx {
                    memo: 0,
                    operation: Some(Op::Transfer {
                        to: vec![1; 32],
                        fee: Tk { e8s: 10_000 },
                        from: vec![2; 32],
                        amount: Tk { e8s: 5 },
                    }),
                },
                timestamp: 1,
            }],
            first_block_index: 7,
        };
        let BlockLookup::Found(t) = parse_query_blocks(&candid::encode_one(q).unwrap()).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            t,
            LedgerTransfer {
                from_hex: hex(&[2; 32]),
                to_hex: hex(&[1; 32]),
                amount_e8s: 5,
                fee_e8s: 10_000
            }
        );
        let mint = Qb {
            blocks: vec![Blk {
                transaction: Tx {
                    memo: 0,
                    operation: Some(Op::Mint(())),
                },
                timestamp: 1,
            }],
            first_block_index: 7,
        };
        assert!(matches!(
            parse_query_blocks(&candid::encode_one(mint).unwrap()).unwrap(),
            BlockLookup::Missing(_)
        ));
        let empty = Qb {
            blocks: vec![],
            first_block_index: 7,
        };
        assert!(matches!(
            parse_query_blocks(&candid::encode_one(empty).unwrap()).unwrap(),
            BlockLookup::Missing(_)
        ));
    }

    #[test]
    fn selects_smallest_positive_dissolved_info_only() {
        let s = snap(
            1,
            vec![
                dissolved_info(1, 500, 3),
                dissolved_info(2, 0, 3),
                dissolved_info(3, 100, 1),
                dissolved_info(4, 300, 3),
                dissolved_info(5, 300, 3),
                full(6, 10, 0, 0, 0),
            ],
        );
        assert_eq!(select_smallest_dissolved(&s), Some((4, 300)));
        assert_eq!(
            select_smallest_dissolved(&snap(1, vec![full(6, 10, 0, 0, 0)])),
            None
        );
    }

    const DEST: &str = "0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed";

    fn transfer(to: &str, amount: u64) -> LedgerTransfer {
        LedgerTransfer {
            from_hex: "aa".repeat(32),
            to_hex: to.into(),
            amount_e8s: amount,
            fee_e8s: 10_000,
        }
    }

    fn gov_err(t: i32) -> GovernanceOutcome {
        GovernanceOutcome::Error {
            error_type: t,
            message: "m".into(),
        }
    }

    #[test]
    fn block_check_requires_exact_recipient_and_amount() {
        assert!(matches!(
            check_block(Ok(BlockLookup::Found(transfer(DEST, 5))), DEST, 5),
            BlockCheck::Verified(_)
        ));
        assert!(matches!(
            check_block(Ok(BlockLookup::Found(transfer(DEST, 6))), DEST, 5),
            BlockCheck::Mismatch { .. }
        ));
        let BlockCheck::Mismatch { why, .. } =
            check_block(Ok(BlockLookup::Found(transfer("bb", 5))), DEST, 5)
        else {
            panic!()
        };
        assert!(why.contains("not the destination account"));
        assert!(matches!(
            check_block(Ok(BlockLookup::Archived), DEST, 5),
            BlockCheck::Unavailable(_)
        ));
        assert!(matches!(
            check_block(Ok(BlockLookup::Missing("x".into())), DEST, 5),
            BlockCheck::Unavailable(_)
        ));
        assert!(matches!(
            check_block(Err("net".into()), DEST, 5),
            BlockCheck::Unavailable(_)
        ));
    }

    #[test]
    fn verdict_never_reports_success_without_verified_ledger_evidence() {
        let ok = GovernanceOutcome::Disbursed {
            transfer_block_height: 9,
        };
        let verified = BlockCheck::Verified(transfer(DEST, 5));
        assert_eq!(decide(Some(&ok), Some(&verified)), Verdict::Success);
        assert_eq!(decide(Some(&ok), None), Verdict::Pending);
        assert_eq!(
            decide(Some(&ok), Some(&BlockCheck::Unavailable("x".into()))),
            Verdict::Pending
        );
        let mismatch = BlockCheck::Mismatch {
            transfer: transfer("bb", 5),
            why: "w".into(),
        };
        assert_eq!(decide(Some(&ok), Some(&mismatch)), Verdict::Unknown);
        // Ledger evidence without an accepted Governance reply is never success either.
        assert_eq!(decide(None, Some(&verified)), Verdict::Unknown);
        assert_eq!(
            decide(Some(&gov_err(3)), Some(&verified)),
            Verdict::RejectedNotAuthorized
        );
    }

    #[test]
    fn verdict_maps_governance_errors_and_unknowns() {
        assert_eq!(
            decide(Some(&gov_err(3)), None),
            Verdict::RejectedNotAuthorized
        );
        assert_eq!(
            decide(Some(&gov_err(9)), None),
            Verdict::RejectedNotAuthorized
        );
        assert_eq!(
            decide(Some(&gov_err(8)), None),
            Verdict::FailedGovernanceError
        );
        assert_eq!(
            decide(Some(&gov_err(14)), None),
            Verdict::FailedGovernanceError
        );
        assert_eq!(
            decide(Some(&GovernanceOutcome::Other("?".into())), None),
            Verdict::Unknown
        );
        assert_eq!(decide(None, None), Verdict::Unknown);
        assert_eq!(
            Verdict::Success.headline(),
            "SUCCESS — LEDGER TRANSFER VERIFIED"
        );
        assert_eq!(
            Verdict::RejectedNotAuthorized.headline(),
            "REJECTED — NOT AUTHORIZED"
        );
        assert_eq!(
            Verdict::FailedGovernanceError.headline(),
            "FAILED — GOVERNANCE ERROR"
        );
        assert_eq!(
            Verdict::Pending.headline(),
            "PENDING — GOVERNANCE ACCEPTED, LEDGER NOT YET VERIFIED"
        );
        assert_eq!(
            Verdict::Unknown.headline(),
            "UNKNOWN — TRANSACTION OUTCOME COULD NOT BE DETERMINED"
        );
    }

    #[test]
    fn timeout_is_unknown_and_never_described_as_failure() {
        let e = ic_agent::AgentError::TimeoutWaitingForResponse();
        let kind = classify_agent_error(&e);
        assert_eq!(kind, "TIMEOUT");
        assert_eq!(decide(None, None), Verdict::Unknown);
        let text = verdict_explanation(Verdict::Unknown, None, Some(kind));
        assert!(text.contains("NOT a failure"));
        assert!(
            !verdict_explanation(Verdict::RejectedNotAuthorized, None, None).contains("timed out")
        );
    }

    #[test]
    fn expectation_notes_flag_matches_and_mismatches() {
        let before = Balances {
            neuron_stake_e8s: 98_000_000,
            dest_e8s: 94_233_666_604,
        };
        let req = 10_000_000;
        let good = Balances {
            neuron_stake_e8s: 88_000_000,
            dest_e8s: 94_243_666_604,
        };
        let n = expectation_notes(&before, Some(&good), req, 10_000).join("\n");
        assert!(
            n.contains("MATCHES expectation")
                && n.contains("exactly the requested amount (the fee was not")
        );
        let with_fee = Balances {
            neuron_stake_e8s: 87_990_000,
            dest_e8s: 94_243_666_604,
        };
        assert!(expectation_notes(&before, Some(&with_fee), req, 10_000)
            .join("\n")
            .contains("plus the ledger fee"));
        let unchanged = expectation_notes(&before, Some(&before), req, 10_000).join("\n");
        assert!(unchanged.contains("did NOT change") && !unchanged.contains("MATCHES"));
        let odd = Balances {
            neuron_stake_e8s: 88_000_000,
            dest_e8s: 94_243_666_605,
        };
        assert!(expectation_notes(&before, Some(&odd), req, 10_000)
            .join("\n")
            .contains("MISMATCH"));
        assert!(expectation_notes(&before, None, req, 10_000)
            .join("\n")
            .contains("could not be read"));
    }

    #[test]
    fn reconciliation_table_shows_signed_deltas_and_unavailable() {
        let before = Balances {
            neuron_stake_e8s: 98_000_000,
            dest_e8s: 94_233_666_604,
        };
        let after = Balances {
            neuron_stake_e8s: 88_000_000,
            dest_e8s: 94_243_666_604,
        };
        let t = transfer(DEST, 10_000_000);
        let s = reconciliation_table(&before, Some(&after), 10_000_000, Some(&t), Some(77));
        assert!(s.contains("-0.10000000 ICP") && s.contains("+0.10000000 ICP"));
        assert!(
            s.contains("0.98000000 ICP")
                && s.contains("942.33666604 ICP")
                && s.contains("942.43666604 ICP")
        );
        assert!(
            s.contains("Ledger block index      : 77")
                && s.contains("Transaction fee         : 0.00010000 ICP")
        );
        let s2 = reconciliation_table(&before, None, 10_000_000, None, None);
        assert!(s2.contains("unavailable") && s2.contains("not verified on the ledger"));
    }

    #[test]
    fn second_submission_for_the_same_neuron_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "neuron-audit-lock-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let intent = serde_json::json!({"x": 1});
        assert!(prior_attempt(&dir, 5).is_none());
        let p = write_lock(&dir, 5, &intent).unwrap();
        assert!(prior_attempt(&dir, 5).is_some());
        assert!(write_lock(&dir, 5, &intent)
            .unwrap_err()
            .to_string()
            .contains("already recorded"));
        assert!(write_lock(&dir, 6, &intent).is_ok());
        std::fs::remove_dir_all(dir).ok();
        assert!(!p.exists());
    }

    #[test]
    fn verification_commands_use_the_verified_identifiers() {
        let c = verify_commands(13_739_920_397_011_050_625, DEST, Some(1234));
        assert!(c.contains("get_neuron_info '(13739920397011050625 : nat64)'"));
        assert!(
            c.contains("rrkah-fqaaa-aaaaa-aaaaq-cai") && c.contains("ryjl3-tyaaa-aaaaa-aaaba-cai")
        );
        assert!(c.contains(&format!(
            "account_balance_dfx '(record {{ account = \"{DEST}\" }})'"
        )));
        assert!(c.contains("start = 1234 : nat64; length = 1 : nat64"));
        assert!(verify_commands(1, DEST, None).contains("<BLOCK_INDEX>"));
        assert_eq!(c.matches("--identity anonymous").count(), 3);
    }
}
