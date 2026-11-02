//! `deposit` commands: auditable recovery of liquid ICP held by the `deposits` canister.
//!
//! Command classes (never mixed):
//! * read-only: `status`, `verify`, `reconcile` (anonymous queries; `status`/`verify` optionally
//!   make one `canister_status` call, which changes nothing);
//! * local preparation: `prepare` (writes only a manifest file);
//! * installation: `install` (dry run by default; `--execute` + exact payload approval);
//! * irreversible transfer: `transfer` (dry run by default; `--execute` + exact payload approval).
//!
//! The Wasm is installed in mode `install` only, into exactly the manifest's canister. The
//! transfer itself is made by that canister, never by this tool.

use crate::deposit_manifest::*;
use crate::governance::{fmt_e8s, fmt_utc};
use crate::recovery::{self, account_id, classify_agent_error, hex, BlockLookup};
use crate::recovery_types::*;
use crate::{now_unix, owner, DEFAULT_IC_URL};
use anyhow::{anyhow, bail, Context, Result};
use candid::{CandidType, Deserialize, IDLArgs, Nat, Principal};
use clap::{Args, Subcommand, ValueEnum};
use ic_agent::{Agent, AgentError, Identity};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, ValueEnum)]
pub enum KindArg {
    /// The 0.1 ICP test transfer
    Test,
    /// The remaining balance, only after a reconciled test transfer
    Final,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StageArg {
    Install,
    Transfer,
}

#[derive(Args)]
pub struct ManifestOpts {
    /// Manifest produced by `deposit prepare`
    #[arg(long)]
    pub manifest: PathBuf,
    /// Reject manifests older than this (seconds)
    #[arg(long, default_value_t = MAX_MANIFEST_AGE_SECS)]
    pub max_age_secs: u64,
}

#[derive(Args)]
pub struct ExecOpts {
    /// Actually send. Without it the command only verifies and shows what it would send.
    #[arg(long)]
    pub execute: bool,
    /// SHA-256 of the exact Candid payload printed by the dry run
    #[arg(long)]
    pub approve_payload_sha256: Option<String>,
    /// PEM of the `sticpowner` identity; `-` reads stdin
    #[arg(long)]
    pub owner_pem: PathBuf,
    #[arg(long, default_value = "audit-out")]
    pub out_dir: PathBuf,
}

#[derive(Subcommand)]
pub enum DepositCommand {
    /// Read-only: state of the source canister, its ledger account and the destination.
    Status {
        /// `sticpowner` PEM: adds `canister_status` (state, cycles, settings). Read-only.
        #[arg(long)]
        owner_pem: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_IC_URL)]
        ic_url: String,
    },
    /// Local: observe mainnet and write a sealed, deterministic manifest. Sends nothing.
    Prepare {
        #[arg(long, value_enum)]
        kind: KindArg,
        /// Recovery Wasm built by recovery-canister/build.sh
        #[arg(long)]
        wasm: PathBuf,
        /// Output manifest (create-only; never overwritten)
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        owner_pem: PathBuf,
        /// Source balance you expect (default: the verified value for this kind)
        #[arg(long)]
        expected_balance_e8s: Option<u64>,
        /// Destination balance you expect (default: the verified value for this kind)
        #[arg(long)]
        expected_destination_balance_e8s: Option<u64>,
        #[arg(long, default_value = DEFAULT_IC_URL)]
        ic_url: String,
    },
    /// Read-only: compare a manifest with the current mainnet state.
    Verify {
        #[command(flatten)]
        m: ManifestOpts,
        #[arg(long, value_enum)]
        stage: StageArg,
        #[arg(long)]
        owner_pem: Option<PathBuf>,
    },
    /// Installs the recovery Wasm (mode `install`) into the empty source canister.
    Install {
        #[command(flatten)]
        m: ManifestOpts,
        #[arg(long)]
        wasm: PathBuf,
        #[command(flatten)]
        x: ExecOpts,
    },
    /// IRREVERSIBLE: asks the recovery canister to send the manifest's amount to the destination.
    Transfer {
        #[command(flatten)]
        m: ManifestOpts,
        #[command(flatten)]
        x: ExecOpts,
    },
    /// Read-only: compare the canister record, the ledger block and both balances to the manifest.
    Reconcile {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "audit-out")]
        out_dir: PathBuf,
    },
}

pub async fn run(c: DepositCommand) -> Result<bool> {
    match c {
        DepositCommand::Status { owner_pem, ic_url } => status(owner_pem, ic_url).await,
        DepositCommand::Prepare {
            kind,
            wasm,
            out,
            owner_pem,
            expected_balance_e8s,
            expected_destination_balance_e8s,
            ic_url,
        } => {
            prepare(
                kind,
                wasm,
                out,
                owner_pem,
                expected_balance_e8s,
                expected_destination_balance_e8s,
                ic_url,
            )
            .await
        }
        DepositCommand::Verify {
            m,
            stage,
            owner_pem,
        } => verify(m, stage, owner_pem).await,
        DepositCommand::Install { m, wasm, x } => install(m, wasm, x).await,
        DepositCommand::Transfer { m, x } => transfer(m, x).await,
        DepositCommand::Reconcile { manifest, out_dir } => reconcile_cmd(manifest, out_dir).await,
    }
}

// ---------- wire types ----------

#[derive(CandidType)]
struct CanisterIdRecord {
    canister_id: Principal,
}

/// The only installation mode this tool can encode.
#[derive(CandidType, Deserialize)]
enum InstallMode {
    #[serde(rename = "install")]
    Install,
}

#[derive(CandidType)]
struct InstallCodeArgs {
    mode: InstallMode,
    canister_id: Principal,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
enum RunState {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

#[derive(CandidType, Deserialize)]
struct SettingsView {
    controllers: Vec<Principal>,
}

#[derive(CandidType, Deserialize)]
struct CanisterStatusView {
    status: RunState,
    module_hash: Option<Vec<u8>>,
    cycles: Nat,
    settings: SettingsView,
}

pub fn encode_install(canister: Principal, wasm: &[u8]) -> Result<Vec<u8>> {
    Ok(candid::encode_one(InstallCodeArgs {
        mode: InstallMode::Install,
        canister_id: canister,
        wasm_module: wasm.to_vec(),
        arg: candid::encode_args(())?,
    })?)
}

fn principal(text: &str) -> Result<Principal> {
    Principal::from_text(text).map_err(|e| anyhow!("bad principal {text}: {e}"))
}

// ---------- reads ----------

fn anon_agent(url: &str) -> Result<Agent> {
    check_ic_url(url)?;
    Ok(Agent::builder().with_url(url.to_string()).build()?)
}

fn owner_agent(pem: &Path, url: &str) -> Result<(Agent, Principal)> {
    check_ic_url(url)?;
    let id = owner::load_owner_identity(pem)?;
    let who = id.sender().map_err(|e| anyhow!(e))?;
    check_identity(&who)?;
    let agent = Agent::builder()
        .with_url(url.to_string())
        .with_boxed_identity(id)
        .build()?;
    Ok((agent, who))
}

async fn query<T: for<'de> Deserialize<'de> + CandidType>(
    agent: &Agent,
    canister: &Principal,
    method: &str,
    arg: Vec<u8>,
) -> Result<T> {
    let bytes = agent
        .query(canister, method)
        .with_arg(arg)
        .call()
        .await
        .with_context(|| format!("query {method} failed"))?;
    Ok(candid::decode_one(&bytes)?)
}

async fn read_module_hash(agent: &Agent, canister: Principal) -> Result<Option<String>> {
    match agent.read_state_canister_module_hash(canister).await {
        Ok(h) => Ok(Some(hex(&h))),
        Err(AgentError::LookupPathAbsent(_)) => Ok(None),
        Err(e) => Err(anyhow!("cannot read the module hash: {e}")),
    }
}

struct StatusRead {
    running: bool,
    module_hash: Option<String>,
    cycles: u64,
    controllers: Vec<String>,
    settings_sha256: String,
}

/// `canister_status` is an update call to the management canister that only the controllers may
/// make; it reads and changes nothing.
async fn read_canister_status(agent: &Agent, canister: Principal) -> Result<StatusRead> {
    let bytes = agent
        .update(&Principal::management_canister(), "canister_status")
        .with_effective_canister_id(canister)
        .with_arg(candid::encode_one(CanisterIdRecord {
            canister_id: canister,
        })?)
        .call_and_wait()
        .await
        .context("management canister_status failed (is the identity a controller?)")?;
    let s: CanisterStatusView = candid::decode_one(&bytes)?;
    let settings = IDLArgs::from_bytes(&bytes)?
        .args
        .first()
        .and_then(|top| recovery::field(top, "settings"))
        .map(|v| v.to_string())
        .ok_or_else(|| anyhow!("canister_status has no settings"))?;
    let mut controllers: Vec<String> = s.settings.controllers.iter().map(|p| p.to_text()).collect();
    controllers.sort();
    controllers.dedup();
    Ok(StatusRead {
        running: matches!(s.status, RunState::Running),
        module_hash: s.module_hash.map(|h| hex(&h)),
        cycles: u64::try_from(&s.cycles.0).map_err(|_| anyhow!("cycles exceed u64"))?,
        controllers,
        settings_sha256: sha256_hex(settings.as_bytes()),
    })
}

async fn ledger_fee(agent: &Agent, ledger: &Principal) -> Result<u64> {
    let fee: Nat = query(agent, ledger, "icrc1_fee", candid::encode_args(())?).await?;
    u64::try_from(&fee.0).map_err(|_| anyhow!("fee exceeds u64"))
}

/// Reads everything the checks need. With `owner` it also calls `canister_status` and requires
/// it to agree with the certified state-tree values.
async fn read_live(anon: &Agent, owner: Option<&Agent>) -> Result<Live> {
    let source = principal(SOURCE_CANISTER)?;
    let ledger = principal(LEDGER_CANISTER)?;
    let tree_hash = read_module_hash(anon, source).await?;
    let mut tree_controllers: Vec<String> = anon
        .read_state_canister_controllers(source)
        .await
        .context("cannot read the controllers")?
        .iter()
        .map(|p| p.to_text())
        .collect();
    tree_controllers.sort();
    tree_controllers.dedup();

    let mut live = Live {
        module_hash: tree_hash.clone(),
        controllers: tree_controllers.clone(),
        source_balance_e8s: recovery::ledger_balance(anon, &ledger, SOURCE_ACCOUNT_ID).await?,
        destination_balance_e8s: recovery::ledger_balance(anon, &ledger, DESTINATION_ACCOUNT_ID)
            .await?,
        ledger_fee_e8s: ledger_fee(anon, &ledger).await?,
        ..Live::default()
    };
    if let Some(agent) = owner {
        let s = read_canister_status(agent, source).await?;
        if s.module_hash != tree_hash {
            bail!(
                "module hash disagrees: canister_status {:?} vs state tree {:?}",
                s.module_hash,
                tree_hash
            );
        }
        if s.controllers != tree_controllers {
            bail!("controllers disagree between canister_status and the state tree");
        }
        live.running = Some(s.running);
        live.cycles = Some(s.cycles);
        live.settings_sha256 = Some(s.settings_sha256);
    }
    if tree_hash.is_some() {
        live.canister_config = query(anon, &source, "get_config", candid::encode_args(())?)
            .await
            .ok();
        live.canister_state = query(anon, &source, "get_state", candid::encode_args(())?)
            .await
            .ok();
    }
    Ok(live)
}

fn print_live(live: &Live) {
    println!(
        "Module hash      : {}",
        live.module_hash
            .as_deref()
            .unwrap_or("None (empty canister)")
    );
    println!("Controllers      : {}", live.controllers.join(", "));
    match live.running {
        Some(r) => println!(
            "Status           : {}",
            if r { "Running" } else { "NOT running" }
        ),
        None => println!("Status           : not read (needs --owner-pem)"),
    }
    match live.cycles {
        Some(c) => println!("Cycles           : {c}"),
        None => println!("Cycles           : not read (needs --owner-pem)"),
    }
    println!(
        "Source ledger    : {SOURCE_ACCOUNT_ID} holds {} ICP ({} e8s)",
        fmt_e8s(live.source_balance_e8s.into()),
        live.source_balance_e8s
    );
    println!(
        "Destination      : {DESTINATION_ACCOUNT_ID} holds {} ICP ({} e8s)",
        fmt_e8s(live.destination_balance_e8s.into()),
        live.destination_balance_e8s
    );
    println!("Ledger fee       : {} e8s", live.ledger_fee_e8s);
    if let Some(s) = &live.canister_state {
        println!(
            "Recovery state   : next operation {}, {} recorded",
            s.next_operation_id,
            s.operations.len()
        );
        for o in &s.operations {
            println!(
                "  op {} amount {} e8s attempts {} : {:?}",
                o.id, o.amount_e8s, o.attempts, o.status
            );
        }
    }
}

fn static_account_checks() -> Result<()> {
    let src = hex(&account_id(&principal(SOURCE_CANISTER)?, None));
    let dst = hex(&account_id(&principal(DESTINATION_PRINCIPAL)?, None));
    if src != SOURCE_ACCOUNT_ID {
        bail!("derived source account {src} != verified {SOURCE_ACCOUNT_ID}");
    }
    if dst != DESTINATION_ACCOUNT_ID {
        bail!("derived destination account {dst} != verified {DESTINATION_ACCOUNT_ID}");
    }
    Ok(())
}

fn report_problems(problems: &[String]) {
    for p in problems {
        println!("BLOCKED          : {p}");
    }
}

// ---------- status ----------

async fn status(owner_pem: Option<PathBuf>, ic_url: String) -> Result<bool> {
    static_account_checks()?;
    let anon = anon_agent(&ic_url)?;
    let owner = match &owner_pem {
        Some(p) => Some(owner_agent(p, &ic_url)?),
        None => None,
    };
    println!("=== deposits canister recovery: STATUS (read-only) ===");
    println!("Network          : {NETWORK} ({ic_url})");
    println!("Source canister  : {SOURCE_CANISTER}");
    println!("Destination      : {DESTINATION_PRINCIPAL} -> account {DESTINATION_ACCOUNT_ID} (derived default account: verified)");
    println!("Authorized caller: {AUTHORIZED_CALLER}");
    let live = read_live(&anon, owner.as_ref().map(|(a, _)| a)).await?;
    print_live(&live);
    let mut problems = Vec::new();
    if !live.controllers.iter().any(|c| c == AUTHORIZED_CALLER) {
        problems.push("the authorized caller is not a controller".to_string());
    }
    if live.running == Some(false) {
        problems.push("canister is not Running".into());
    }
    if live.ledger_fee_e8s != LEDGER_FEE_E8S {
        problems.push(format!(
            "ledger fee is {} e8s, expected {LEDGER_FEE_E8S}",
            live.ledger_fee_e8s
        ));
    }
    if live.source_balance_e8s != EXPECTED_SOURCE_BALANCE_E8S {
        println!("NOTE             : balance differs from the 2026-11-02 verified {EXPECTED_SOURCE_BALANCE_E8S} e8s (informational)");
    }
    if owner.is_some() {
        println!(
            "Identity         : {AUTHORIZED_CALLER} (matches; is a controller: {})",
            live.controllers.iter().any(|c| c == AUTHORIZED_CALLER)
        );
    }
    report_problems(&problems);
    Ok(problems.is_empty())
}

// ---------- prepare ----------

async fn prepare(
    kind: KindArg,
    wasm: PathBuf,
    out: PathBuf,
    owner_pem: PathBuf,
    expected_balance: Option<u64>,
    expected_destination: Option<u64>,
    ic_url: String,
) -> Result<bool> {
    static_account_checks()?;
    let anon = anon_agent(&ic_url)?;
    let (owner, _) = owner_agent(&owner_pem, &ic_url)?;
    let bytes = std::fs::read(&wasm).with_context(|| format!("cannot read {}", wasm.display()))?;
    if !bytes.starts_with(b"\0asm") {
        bail!("{} is not a WebAssembly module", wasm.display());
    }
    let live = read_live(&anon, Some(&owner)).await?;
    let (kind, default_src, default_dst, stage) = match kind {
        KindArg::Test => (
            Kind::Test,
            EXPECTED_SOURCE_BALANCE_E8S,
            EXPECTED_DESTINATION_BALANCE_E8S,
            Stage::Install,
        ),
        KindArg::Final => (
            Kind::Final,
            EXPECTED_SOURCE_BALANCE_E8S - TEST_TRANSFER_E8S - LEDGER_FEE_E8S,
            EXPECTED_DESTINATION_BALANCE_E8S + TEST_TRANSFER_E8S,
            Stage::Transfer,
        ),
    };
    let want_src = expected_balance.unwrap_or(default_src);
    let want_dst = expected_destination.unwrap_or(default_dst);
    if live.source_balance_e8s != want_src {
        bail!(
            "source balance is {} e8s but {want_src} e8s was expected; investigate, then pass --expected-balance-e8s explicitly",
            live.source_balance_e8s
        );
    }
    if live.destination_balance_e8s != want_dst {
        bail!(
            "destination balance is {} e8s but {want_dst} e8s was expected; pass --expected-destination-balance-e8s explicitly if this is understood",
            live.destination_balance_e8s
        );
    }
    let operation_id = match (&kind, &live.canister_state) {
        (Kind::Test, _) => 1,
        (Kind::Final, Some(s)) => s.next_operation_id,
        (Kind::Final, None) => {
            bail!("the recovery canister is not installed; a final manifest needs it")
        }
    };
    let sha = sha256_hex(&bytes);
    let now = now_unix();
    let m = build(PrepareInput {
        kind,
        ic_url: &ic_url,
        now_unix: now,
        utc: fmt_utc(now),
        live: &live,
        wasm_sha256: sha.clone(),
        wasm_size: bytes.len() as u64,
        operation_id,
    })?;
    let mut problems = check_invariants(&m.body);
    problems.extend(check_live(&m.body, stage, &live, true));
    print_live(&live);
    println!(
        "Wasm             : {} ({} bytes) sha256 {sha}",
        wasm.display(),
        bytes.len()
    );
    println!("Plan             : {}", describe_plan(&m.body));
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("preflight failed; no manifest written");
    }
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .with_context(|| {
            format!(
                "{} already exists; manifests are never overwritten",
                out.display()
            )
        })?;
    f.write_all(&serde_json::to_vec_pretty(&m)?)?;
    f.sync_all()?;
    println!("Manifest written : {}", out.display());
    println!("manifest_sha256  : {}", m.manifest_sha256);
    println!("Nothing was installed or sent. Next: `deposit verify`, then review the manifest.");
    Ok(true)
}

// ---------- verify ----------

struct Checked {
    manifest: Manifest,
    anon: Agent,
}

fn load_checked(m: &ManifestOpts) -> Result<Checked> {
    let manifest = Manifest::load(&m.manifest)?;
    let mut problems = check_invariants(&manifest.body);
    if let Err(e) = check_freshness(&manifest.body, now_unix(), m.max_age_secs) {
        problems.push(e.to_string());
    }
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("manifest {} failed its invariants", m.manifest.display());
    }
    let anon = anon_agent(&manifest.body.network.ic_url)?;
    println!(
        "Manifest         : {} (hash {} verified)",
        m.manifest.display(),
        manifest.manifest_sha256
    );
    println!("Plan             : {}", describe_plan(&manifest.body));
    Ok(Checked { manifest, anon })
}

async fn verify(m: ManifestOpts, stage: StageArg, owner_pem: Option<PathBuf>) -> Result<bool> {
    static_account_checks()?;
    let c = load_checked(&m)?;
    let url = c.manifest.body.network.ic_url.clone();
    let owner = match &owner_pem {
        Some(p) => Some(owner_agent(p, &url)?),
        None => None,
    };
    let live = read_live(&c.anon, owner.as_ref().map(|(a, _)| a)).await?;
    print_live(&live);
    let stage = match stage {
        StageArg::Install => Stage::Install,
        StageArg::Transfer => Stage::Transfer,
    };
    let problems = check_live(&c.manifest.body, stage, &live, owner.is_some());
    report_problems(&problems);
    if owner.is_none() {
        println!("PARTIAL          : canister status, settings and cycles were NOT checked (no --owner-pem); execution commands always check them");
        return Ok(false);
    }
    if problems.is_empty() {
        println!("VERIFIED         : the manifest matches mainnet for stage {stage:?}");
    }
    Ok(problems.is_empty())
}

// ---------- journal ----------

fn journal_path(out_dir: &Path, what: &str, manifest_sha: &str, ext: &str) -> PathBuf {
    out_dir
        .join("deposit")
        .join("journal")
        .join(format!("{what}-{manifest_sha}.{ext}.json"))
}

fn write_create_new(path: &Path, v: &serde_json::Value) -> Result<()> {
    std::fs::create_dir_all(path.parent().ok_or_else(|| anyhow!("no parent"))?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("{} already exists", path.display()))?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    Ok(())
}

fn check_no_prior_attempt(out_dir: &Path, what: &str, sha: &str) -> Result<()> {
    let p = journal_path(out_dir, what, sha, "intent");
    if p.exists() {
        bail!(
            "an {what} attempt for this manifest is already recorded at {}; refusing to send again. Run `deposit reconcile` and read the README before doing anything else",
            p.display()
        );
    }
    Ok(())
}

fn approve(opts: &ExecOpts, payload_sha: &str) -> Result<()> {
    match opts.approve_payload_sha256.as_deref() {
        Some(h) if h.eq_ignore_ascii_case(payload_sha) => Ok(()),
        Some(_) => bail!("--approve-payload-sha256 does not match the payload above; refusing"),
        None => bail!("--execute requires --approve-payload-sha256 {payload_sha}"),
    }
}

// ---------- install ----------

async fn install(m: ManifestOpts, wasm_path: PathBuf, x: ExecOpts) -> Result<bool> {
    static_account_checks()?;
    let c = load_checked(&m)?;
    let b = &c.manifest.body;
    let wasm = std::fs::read(&wasm_path)
        .with_context(|| format!("cannot read {}", wasm_path.display()))?;
    if sha256_hex(&wasm) != b.wasm.sha256 || wasm.len() as u64 != b.wasm.size_bytes {
        bail!(
            "{} does not match the manifest's wasm hash/size",
            wasm_path.display()
        );
    }
    let (owner, who) = owner_agent(&x.owner_pem, &b.network.ic_url)?;
    let target = principal(&b.install.target_canister)?;
    let payload = encode_install(target, &wasm)?;
    let payload_sha = sha256_hex(&payload);

    let live = read_live(&c.anon, Some(&owner)).await?;
    print_live(&live);
    println!("=== INSTALL (mode install, no reinstall/upgrade) into {target} ===");
    println!("Call             : management canister `install_code` as {who}");
    println!("Payload          : mode=install canister_id={target} wasm_module=<{} bytes, sha256 {}> arg=<empty candid>", wasm.len(), b.wasm.sha256);
    println!("Payload SHA-256  : {payload_sha}");
    println!(
        "Preserved        : controllers {:?} and all canister settings (verified before and after)",
        b.source.controllers
    );
    let problems = check_live(b, Stage::Install, &live, true);
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("pre-install checks failed; nothing was sent");
    }
    check_no_prior_attempt(&x.out_dir, "install", &c.manifest.manifest_sha256)?;
    if !x.execute {
        println!("DRY RUN: nothing sent. To approve exactly this installation re-run with:");
        println!("  --execute --approve-payload-sha256 {payload_sha}");
        return Ok(true);
    }
    approve(&x, &payload_sha)?;

    // Verification immediately before the call.
    let fresh = read_live(&c.anon, Some(&owner)).await?;
    let problems = check_live(b, Stage::Install, &fresh, true);
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("state changed since the first check; nothing was sent");
    }
    let t = now_unix();
    write_create_new(
        &journal_path(&x.out_dir, "install", &c.manifest.manifest_sha256, "intent"),
        &serde_json::json!({
            "kind": "install", "manifest_sha256": c.manifest.manifest_sha256,
            "payload_sha256": payload_sha, "canister": target.to_text(),
            "identity": who.to_text(), "unix_secs": t, "utc": fmt_utc(t),
        }),
    )?;
    println!("Sending install_code ...");
    let reply = owner
        .update(&Principal::management_canister(), "install_code")
        .with_effective_canister_id(target)
        .with_arg(payload)
        .call_and_wait()
        .await;
    let (transport, detail) = match &reply {
        Ok(_) => ("OK", String::new()),
        Err(e) => (classify_agent_error(e), e.to_string()),
    };
    if reply.is_err() {
        println!("No confirmed reply: {transport}: {detail}\nThis does NOT prove failure. DO NOT RETRY: check the module hash below.");
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = read_live(&c.anon, Some(&owner)).await;
    let (ok, why) = match &after {
        Ok(l) => post_install_verdict(b, l),
        Err(e) => (false, format!("could not re-read state: {e:#}")),
    };
    if let Ok(l) = &after {
        print_live(l);
    }
    println!(
        "{}",
        if ok {
            "INSTALLED AND VERIFIED"
        } else {
            "NOT VERIFIED"
        }
    );
    println!("{why}");
    let t = now_unix();
    write_create_new(
        &journal_path(&x.out_dir, "install", &c.manifest.manifest_sha256, "result"),
        &serde_json::json!({
            "manifest_sha256": c.manifest.manifest_sha256, "transport": transport, "detail": detail,
            "verified": ok, "verdict": why, "unix_secs": t, "utc": fmt_utc(t),
        }),
    )?;
    Ok(ok)
}

fn post_install_verdict(b: &Body, l: &Live) -> (bool, String) {
    let mut p = Vec::new();
    if l.module_hash.as_deref() != Some(&b.wasm.sha256) {
        p.push(format!(
            "module hash is {:?}, expected {}",
            l.module_hash, b.wasm.sha256
        ));
    }
    if l.controllers != b.source.controllers {
        p.push("controllers changed".to_string());
    }
    if l.settings_sha256.as_deref() != Some(&b.source.settings_sha256) {
        p.push("canister settings changed".into());
    }
    if l.running != Some(true) {
        p.push("canister is not running".into());
    }
    if l.source_balance_e8s != b.source.balance_e8s {
        p.push("source balance changed".into());
    }
    match (&l.canister_config, &l.canister_state) {
        (Some(_), Some(s)) if s.operations.is_empty() && s.next_operation_id == 1 => {}
        _ => p.push("the installed module does not report an initial recovery state".into()),
    }
    if p.is_empty() {
        (true, "Module hash equals the manifest's Wasm, controllers/settings preserved, recovery state initialised.".into())
    } else {
        (false, p.join("; "))
    }
}

// ---------- transfer ----------

async fn transfer(m: ManifestOpts, x: ExecOpts) -> Result<bool> {
    static_account_checks()?;
    let c = load_checked(&m)?;
    let b = &c.manifest.body;
    let (owner, who) = owner_agent(&x.owner_pem, &b.network.ic_url)?;
    let source = principal(SOURCE_CANISTER)?;
    let request = c.manifest.transfer_request()?;
    let payload = candid::encode_one(&request)?;
    let payload_sha = sha256_hex(&payload);

    let live = read_live(&c.anon, Some(&owner)).await?;
    print_live(&live);
    println!("=== TRANSFER (IRREVERSIBLE once executed) ===");
    println!("Call             : update {source}.transfer as {who}");
    println!("Payload (candid) : {}", IDLArgs::from_bytes(&payload)?);
    println!("Payload SHA-256  : {payload_sha}");
    println!("Effect           : the canister sends {} e8s from its default account {SOURCE_ACCOUNT_ID} to {DESTINATION_ACCOUNT_ID} (fixed in the Wasm) and pays a {} e8s fee",
        request.amount_e8s, request.expected_fee_e8s);
    let problems = check_live(b, Stage::Transfer, &live, true);
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("pre-transfer checks failed; nothing was sent");
    }
    check_no_prior_attempt(&x.out_dir, "transfer", &c.manifest.manifest_sha256)?;
    if !x.execute {
        println!("DRY RUN: nothing sent. To approve exactly this transfer re-run with:");
        println!("  --execute --approve-payload-sha256 {payload_sha}");
        return Ok(true);
    }
    approve(&x, &payload_sha)?;

    let fresh = read_live(&c.anon, Some(&owner)).await?;
    let problems = check_live(b, Stage::Transfer, &fresh, true);
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("state changed since the first check; nothing was sent");
    }
    let t = now_unix();
    write_create_new(
        &journal_path(
            &x.out_dir,
            "transfer",
            &c.manifest.manifest_sha256,
            "intent",
        ),
        &serde_json::json!({
            "kind": "transfer", "manifest_sha256": c.manifest.manifest_sha256,
            "payload_sha256": payload_sha, "operation_id": request.expected_operation_id,
            "amount_e8s": request.amount_e8s, "identity": who.to_text(), "unix_secs": t, "utc": fmt_utc(t),
        }),
    )?;
    println!("Sending transfer ...");
    let reply = owner
        .update(&source, "transfer")
        .with_arg(payload)
        .call_and_wait()
        .await;
    let (transport, detail, outcome) = match &reply {
        Ok(bytes) => match candid::decode_one::<Result<TransferOk, RecoveryError>>(bytes) {
            Ok(Ok(ok)) => (
                "OK",
                String::new(),
                format!(
                    "canister reports success: operation {} block {} duplicate={}",
                    ok.operation_id, ok.block_index, ok.duplicate
                ),
            ),
            Ok(Err(e)) => (
                "OK",
                String::new(),
                format!("canister reports error: {e:?}"),
            ),
            Err(e) => ("OK", String::new(), format!("undecodable reply: {e}")),
        },
        Err(e) => (
            classify_agent_error(e),
            e.to_string(),
            "no usable reply: the transfer MAY have executed".to_string(),
        ),
    };
    println!("Canister reply   : {outcome}");
    if reply.is_err() {
        println!("DO NOT RETRY blindly. The canister's own state is authoritative: see `deposit reconcile`.");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let verdict = reconcile_report(&c.manifest, &c.anon, &x.out_dir).await?;
    let t = now_unix();
    write_create_new(
        &journal_path(
            &x.out_dir,
            "transfer",
            &c.manifest.manifest_sha256,
            "result",
        ),
        &serde_json::json!({
            "manifest_sha256": c.manifest.manifest_sha256, "transport": transport, "detail": detail,
            "canister_reply": outcome, "verdict": verdict, "unix_secs": t, "utc": fmt_utc(t),
        }),
    )?;
    Ok(verdict == Verdict::Reconciled)
}

// ---------- reconcile ----------

async fn reconcile_cmd(manifest: PathBuf, out_dir: PathBuf) -> Result<bool> {
    static_account_checks()?;
    let m = Manifest::load(&manifest)?;
    let problems = check_invariants(&m.body);
    if !problems.is_empty() {
        report_problems(&problems);
        bail!("manifest failed its invariants");
    }
    let anon = anon_agent(&m.body.network.ic_url)?;
    println!(
        "Manifest         : {} (hash {} verified)",
        manifest.display(),
        m.manifest_sha256
    );
    println!("Plan             : {}", describe_plan(&m.body));
    let v = reconcile_report(&m, &anon, &out_dir).await?;
    Ok(v == Verdict::Reconciled)
}

async fn block_evidence(anon: &Agent, b: &Body, op: &Operation, block: &Nat) -> BlockEvidence {
    let Ok(height) = u64::try_from(&block.0) else {
        return BlockEvidence::Unavailable("block index exceeds u64".into());
    };
    let Ok(ledger) = principal(LEDGER_CANISTER) else {
        return BlockEvidence::Unavailable("bad ledger".into());
    };
    let mut last = BlockEvidence::Unavailable("not attempted".into());
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        last = match recovery::ledger_block(anon, &ledger, height).await {
            Ok(BlockLookup::Found(t)) => {
                let mut why = Vec::new();
                if t.from_hex != b.source.account_id {
                    why.push(format!("sender {} is not the source account", t.from_hex));
                }
                if t.to_hex != b.destination.account_id {
                    why.push(format!(
                        "recipient {} is not the destination account",
                        t.to_hex
                    ));
                }
                if t.amount_e8s != op.amount_e8s || t.amount_e8s != b.transfer.amount_e8s {
                    why.push(format!("amount {} e8s differs", t.amount_e8s));
                }
                if t.fee_e8s != b.transfer.fee_e8s {
                    why.push(format!("fee {} e8s differs", t.fee_e8s));
                }
                if why.is_empty() {
                    BlockEvidence::Verified
                } else {
                    BlockEvidence::Mismatch(why.join("; "))
                }
            }
            Ok(BlockLookup::Archived) => BlockEvidence::Unavailable(
                "block is in an archive canister; verify with query_blocks / the dashboard".into(),
            ),
            Ok(BlockLookup::Missing(m)) => BlockEvidence::Unavailable(m),
            Err(e) => BlockEvidence::Unavailable(e.to_string()),
        };
        if !matches!(last, BlockEvidence::Unavailable(_)) {
            break;
        }
    }
    last
}

async fn reconcile_report(m: &Manifest, anon: &Agent, out_dir: &Path) -> Result<Verdict> {
    let b = &m.body;
    let source = principal(SOURCE_CANISTER)?;
    let ledger = principal(LEDGER_CANISTER)?;
    let state: State = query(anon, &source, "get_state", candid::encode_args(())?)
        .await
        .context("cannot read the recovery canister's state (is it installed?)")?;
    let src_now = recovery::ledger_balance(anon, &ledger, SOURCE_ACCOUNT_ID).await?;
    let dst_now = recovery::ledger_balance(anon, &ledger, DESTINATION_ACCOUNT_ID).await?;
    let op = state
        .operations
        .iter()
        .find(|o| o.id == b.transfer.operation_id);
    let evidence = match op.map(|o| (o, &o.status)) {
        Some((o, Status::Completed { block_index, .. })) => {
            block_evidence(anon, b, o, block_index).await
        }
        _ => BlockEvidence::NotChecked,
    };
    let r = reconcile(b, state.next_operation_id, op, src_now, dst_now, &evidence);

    println!();
    println!("--- Reconciliation (canister record, ledger block, balances) ---");
    println!(
        "Canister record : {:?}",
        op.map(|o| (&o.status, o.attempts))
    );
    println!("Ledger block    : {evidence:?}");
    println!(
        "Source          : {} -> {} e8s (expected {})",
        b.source.balance_e8s, src_now, b.transfer.expected_source_balance_after_e8s
    );
    println!(
        "Destination     : {} -> {} e8s (expected {})",
        b.destination.balance_e8s, dst_now, b.transfer.expected_destination_balance_after_e8s
    );
    for n in &r.notes {
        println!("  * {n}");
    }
    println!("VERDICT         : {:?}", r.verdict);
    match r.verdict {
        Verdict::InDoubt => {
            println!("Do NOT send anything new. See README: \"Failure and recovery\".")
        }
        Verdict::Discrepancy | Verdict::Unverified => {
            println!("Stop and investigate before any further action.")
        }
        _ => {}
    }

    let t = now_unix();
    let report = serde_json::json!({
        "manifest_sha256": m.manifest_sha256, "verdict": r.verdict, "notes": r.notes,
        "source_balance_e8s": src_now, "destination_balance_e8s": dst_now,
        "source_delta_e8s": r.source_delta_e8s.to_string(), "destination_delta_e8s": r.destination_delta_e8s.to_string(),
        "canister_operation": op.map(|o| format!("{o:?}")), "ledger_block": format!("{evidence:?}"),
        "unix_secs": t, "utc": fmt_utc(t),
    });
    let path = out_dir
        .join("deposit")
        .join(format!("reconcile-{}-{t}.json", m.manifest_sha256));
    write_create_new(&path, &report)?;
    println!("Report          : {}", path.display());
    Ok(r.verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_payload_can_only_be_mode_install_for_the_target() {
        let target = principal(SOURCE_CANISTER).unwrap();
        let bytes = encode_install(target, b"\0asm\x01\0\0\0").unwrap();
        let text = IDLArgs::from_bytes(&bytes).unwrap().to_string();
        // Candid prints variant labels by hash: only `install` may appear.
        assert_eq!(candid::idl_hash("install"), 2_375_734_555);
        assert!(text.contains("variant { 2_375_734_555 }"), "{text}");
        assert_ne!(candid::idl_hash("reinstall"), 2_375_734_555);
        assert!(text.contains(SOURCE_CANISTER));
        assert_eq!(sha256_hex(&bytes).len(), 64);
        // The tool encodes an empty init argument.
        let other = encode_install(
            principal(DESTINATION_PRINCIPAL).unwrap(),
            b"\0asm\x01\0\0\0",
        )
        .unwrap();
        assert_ne!(bytes, other);
    }

    #[test]
    fn transfer_payload_has_no_recipient_field() {
        let m = tests_manifest();
        let payload = candid::encode_one(m.transfer_request().unwrap()).unwrap();
        let text = IDLArgs::from_bytes(&payload).unwrap().to_string();
        assert!(!text.contains("principal"), "{text}");
        assert_eq!(sha256_hex(&payload), sha256_hex(&payload));
    }

    fn tests_manifest() -> Manifest {
        crate::deposit_manifest::tests::test_manifest()
    }

    #[test]
    fn journal_paths_are_per_manifest_and_stage() {
        let a = journal_path(Path::new("out"), "install", "abc", "intent");
        let b = journal_path(Path::new("out"), "transfer", "abc", "intent");
        assert_ne!(a, b);
        assert!(a.ends_with("deposit/journal/install-abc.intent.json"));
    }

    #[test]
    fn prior_attempt_blocks_a_second_send_and_files_are_create_only() {
        let dir = std::env::temp_dir().join(format!(
            "deposit-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        assert!(check_no_prior_attempt(&dir, "transfer", "h").is_ok());
        write_create_new(
            &journal_path(&dir, "transfer", "h", "intent"),
            &serde_json::json!({}),
        )
        .unwrap();
        assert!(check_no_prior_attempt(&dir, "transfer", "h").is_err());
        assert!(write_create_new(
            &journal_path(&dir, "transfer", "h", "intent"),
            &serde_json::json!({})
        )
        .is_err());
        assert!(check_no_prior_attempt(&dir, "install", "h").is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn approval_must_match_the_exact_payload_hash() {
        let opts = |h: Option<&str>| ExecOpts {
            execute: true,
            approve_payload_sha256: h.map(str::to_string),
            owner_pem: PathBuf::from("-"),
            out_dir: PathBuf::from("x"),
        };
        assert!(approve(&opts(Some("ABC")), "abc").is_ok());
        assert!(approve(&opts(Some("abd")), "abc").is_err());
        assert!(approve(&opts(None), "abc").is_err());
    }

    #[test]
    fn post_install_verdict_requires_wasm_preserved_state_and_initial_recovery_state() {
        let m = tests_manifest();
        let b = &m.body;
        let mut l = crate::deposit_manifest::tests::live_empty();
        l.module_hash = Some(b.wasm.sha256.clone());
        l.canister_config = Some(ConfigView {
            source_canister: principal(SOURCE_CANISTER).unwrap(),
            authorized_caller: principal(AUTHORIZED_CALLER).unwrap(),
            destination: principal(DESTINATION_PRINCIPAL).unwrap(),
            ledger: principal(LEDGER_CANISTER).unwrap(),
            fee_e8s: LEDGER_FEE_E8S,
            max_operations: MAX_OPERATIONS as u64,
        });
        l.canister_state = Some(State::new());
        assert!(post_install_verdict(b, &l).0);
        let mut bad = l.clone();
        bad.module_hash = None;
        assert!(!post_install_verdict(b, &bad).0);
        let mut bad = l.clone();
        bad.controllers.pop();
        assert!(!post_install_verdict(b, &bad).0);
        let mut bad = l.clone();
        bad.canister_state = None;
        assert!(!post_install_verdict(b, &bad).0);
        let _ = fmt_utc(0);
    }
}
