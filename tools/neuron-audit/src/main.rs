//! neuron-audit — audit of the stICP NNS neurons with gated StartDissolving.
//! Stage A (`identity`): derive the Oracle principal; no signatures, no Governance.
//! Stage B (`inspect`): one signed `list_neurons` query for one neuron.
//! Stage C (`audit`, `report`, `inventory`): budgeted multi-neuron snapshots and history.
//! Dissolution updates are pinned to one validated StartDissolving payload; the separate
//! recovery command retains its independently guarded Disburse capability.

mod audit;
mod control;
mod deposit;
mod deposit_manifest;
// Compiled from the recovery canister's source so constants and wire types cannot drift.
#[allow(dead_code)]
#[path = "../recovery-canister/src/types.rs"]
mod recovery_types;
mod dissolve;
mod governance;
mod history;
mod identity;
mod inventory;
mod owner;
mod recovery;
mod report;
mod session;
mod signer;
mod snapshot;
mod sync;

use anyhow::{anyhow, bail, Context, Result};
use candid::Principal;
use clap::{Args, Parser, Subcommand};
use ic_agent::Agent;
use sha2::Digest;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_IC_URL: &str = "https://icp0.io";
const DEFAULT_SIGNING: &str = "onfif-zaaaa-aaaar-qaama-cai";
const DEFAULT_GOVERNANCE: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";
const DEFAULT_OWNER: &str = "pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe";
const DEFAULT_DEPOSITS: &str = "hnwvc-lyaaa-aaaal-aaf6q-cai";
/// Query + at most one subnet-key `read_state` + one spare.
const INSPECT_MAX_SIGNATURES: u32 = 3;
/// Absolute ceiling for one `audit` run.
const AUDIT_MAX_SIGNATURES: u32 = 100;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Arguments shared by the authenticated commands.
#[derive(Args)]
struct Net {
    /// PEM of the local owner identity (the `signing` owner); `-` reads stdin
    #[arg(long)]
    owner_pem: PathBuf,
    #[arg(long, default_value = DEFAULT_SIGNING)]
    signing: String,
    #[arg(long, default_value = DEFAULT_GOVERNANCE)]
    governance: String,
    /// Principal the owner PEM must correspond to (checked before any network call)
    #[arg(long, default_value = DEFAULT_OWNER)]
    owner_principal: String,
    /// Historical Oracle principal; the signing canister's key must match it
    #[arg(long, default_value = identity::HISTORICAL_ORACLE_PRINCIPAL)]
    expected: String,
    #[arg(long, default_value = DEFAULT_IC_URL)]
    ic_url: String,
}

#[derive(Args)]
struct ReportOpts {
    /// Output directory (snapshots/ , neurons-latest.csv, summary-latest.md)
    #[arg(long, default_value = "audit-out")]
    out_dir: PathBuf,
    /// Minimum snapshot spacing for a return to be computed
    #[arg(long, default_value_t = 86_400)]
    min_interval_secs: u64,
    /// Gross protocol share of staking rewards, in basis points (1000 = 10%)
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u32).range(0..=10_000))]
    protocol_share_bps: u32,
}

#[derive(Args)]
struct ControlOpts {
    #[arg(long, default_value = "audit-out")]
    out_dir: PathBuf,
    /// Baseline snapshot file (default: the latest in <out-dir>/snapshots)
    #[arg(long)]
    snapshot: Option<PathBuf>,
    /// Extra known principals as LABEL=PRINCIPAL (repeatable)
    #[arg(long = "known")]
    known: Vec<String>,
    #[arg(long, default_value = DEFAULT_DEPOSITS)]
    deposits: String,
    #[arg(long, default_value = DEFAULT_SIGNING)]
    signing_canister: String,
    #[arg(long, default_value = DEFAULT_OWNER)]
    local_owner: String,
}

#[derive(Subcommand)]
enum Command {
    /// Auditable recovery of liquid ICP from the `deposits` canister (status/prepare/verify/install/transfer/reconcile).
    Deposit {
        #[command(subcommand)]
        command: deposit::DepositCommand,
    },
    /// Controlled StartDissolving workflow (plan is read-only; writes require --execute).
    Dissolve {
        #[command(subcommand)]
        command: DissolveCommand,
    },
    /// Derive the Oracle's self-authenticating principal from the signing canister's public key.
    Identity {
        /// Principal of the ECDSA signing canister
        #[arg(long)]
        signing: String,
        /// Expected (historical) Oracle principal
        #[arg(long, default_value = identity::HISTORICAL_ORACLE_PRINCIPAL)]
        expected: String,
        /// IC API URL (mainnet; the agent uses the built-in mainnet root key)
        #[arg(long, default_value = DEFAULT_IC_URL)]
        ic_url: String,
    },
    /// Read-only: one signed `list_neurons` query for ONE neuron, as the Oracle ECDSA identity.
    /// Without --confirm-signing this is a dry run that performs no signing.
    Inspect {
        /// The single neuron ID to inspect
        #[arg(long)]
        neuron_id: u64,
        /// Authorize spending ECDSA signatures (cycles of the signing canister)
        #[arg(long)]
        confirm_signing: bool,
        /// Hard cap on signatures for this run
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=3))]
        max_signatures: u32,
        #[command(flatten)]
        net: Net,
    },
    /// Offline: parse a neuron ID file and print original/unique counts and the signature plan.
    /// Without a subcommand: offline parse of --ids-file. `inventory sync` maintains the canonical
    /// audit-in/neurons.txt from trusted sources (offline, never touches the network).
    #[command(args_conflicts_with_subcommands = true)]
    Inventory {
        #[command(subcommand)]
        command: Option<InventoryCommand>,
        #[arg(long)]
        ids_file: Option<PathBuf>,
        #[arg(long, default_value_t = 10, value_parser = parse_batch_size)]
        batch_size: usize,
    },
    /// Read-only: batched signed `list_neurons` queries for every ID in a file, saved as an
    /// immutable snapshot, then CSV/Markdown reports. Without --confirm-signing: dry run.
    Audit {
        /// Text file with neuron IDs (plain list or the bash array in check-neurons.sh)
        #[arg(long)]
        ids_file: PathBuf,
        #[arg(long, default_value_t = 10, value_parser = parse_batch_size)]
        batch_size: usize,
        /// Hard cap on ECDSA signatures for the whole run (required; no default)
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=AUDIT_MAX_SIGNATURES as i64))]
        max_signatures: u32,
        /// Authorize spending ECDSA signatures (cycles of the signing canister)
        #[arg(long)]
        confirm_signing: bool,
        #[command(flatten)]
        net: Net,
        #[command(flatten)]
        opts: ReportOpts,
    },
    /// EXPLICITLY AUTHORIZED RECOVERY TEST: one `Disburse` of one dissolved neuron to the deposits
    /// canister's ledger account. Default mode only prepares (anonymous reads, nothing signed).
    RecoverDisburse(Box<recovery::DisburseArgs>),
    /// Offline: reconcile access/control for every neuron in the baseline snapshot (plus the latest
    /// probe, if any) and write control-report.md / control-report.json. Never touches the network.
    Control {
        #[command(flatten)]
        ctl: ControlOpts,
    },
    /// Read-only: `get_full_neuron` (signed query) for each neuron the baseline could only see as
    /// `info_only`. Without --confirm-signing: dry run. Saves an immutable probe file, then
    /// regenerates the control report.
    Probe {
        /// Hard cap on ECDSA signatures (required; needs >= neurons to probe + 2)
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=AUDIT_MAX_SIGNATURES as i64))]
        max_signatures: u32,
        #[arg(long)]
        confirm_signing: bool,
        #[command(flatten)]
        net: Net,
        #[command(flatten)]
        ctl: ControlOpts,
    },
    /// Offline: regenerate CSV/Markdown from the saved snapshots. Never touches the network.
    Report {
        #[command(flatten)]
        opts: ReportOpts,
    },
}

#[derive(Subcommand)]
enum InventoryCommand {
    /// Merge the existing canonical inventory with IDs from trusted sources. Deterministic,
    /// idempotent and non-destructive (existing IDs are never removed).
    Sync {
        /// Directory holding the canonical neurons.txt (default: crate audit-in/)
        #[arg(long)]
        input_dir: Option<PathBuf>,
        /// Canonical output file (default: <input-dir>/neurons.txt)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also import the built-in trusted historical sources (recovery script/CSV, audit
        /// snapshots, control/trace reports, disburse records)
        #[arg(long)]
        include_history: bool,
        /// Extra explicit source: KIND=PATH (bash-array|csv|snapshot|control-report|
        /// controller-trace|disburse). Repeatable.
        #[arg(long = "source", value_name = "KIND=PATH")]
        sources: Vec<String>,
        /// Report file (default: crate audit-out/inventory-report.md)
        #[arg(long)]
        report: Option<PathBuf>,
        /// Show what would change without writing anything
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum DissolveCommand {
    Plan {
        /// Candidate neuron IDs (default: tools/neuron-audit/audit-in/neurons.txt, resolved from
        /// the crate location). Candidates only; control is verified fresh against the NNS.
        #[arg(long)]
        ids_file: Option<PathBuf>,
        #[arg(long, default_value = "audit-out")]
        out_dir: PathBuf,
        #[arg(long)]
        owner_pem: PathBuf,
        #[arg(long, default_value=DEFAULT_SIGNING)]
        signing: String,
        #[arg(long, default_value=DEFAULT_GOVERNANCE)]
        governance: String,
        #[arg(long, default_value=DEFAULT_OWNER)]
        owner_principal: String,
        #[arg(long, default_value=identity::HISTORICAL_ORACLE_PRINCIPAL)]
        expected: String,
        #[arg(long, default_value=DEFAULT_IC_URL)]
        ic_url: String,
    },
    Start {
        #[arg(long)]
        neuron_id: u64,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        owner_pem: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long, default_value=DEFAULT_SIGNING)]
        signing: String,
        #[arg(long, default_value=DEFAULT_GOVERNANCE)]
        governance: String,
        #[arg(long, default_value=DEFAULT_OWNER)]
        owner_principal: String,
        #[arg(long, default_value=identity::HISTORICAL_ORACLE_PRINCIPAL)]
        expected: String,
        #[arg(long, default_value=DEFAULT_IC_URL)]
        ic_url: String,
        #[arg(long, default_value = "audit-out")]
        out_dir: PathBuf,
    },
    /// Read-only reconciliation of a journaled neuron whose result was mis-classified
    /// (`governance_rejected` / `missing command response`, the old decoder bug). Performs a
    /// fresh signed `list_neurons` query and, only if the neuron is verifiably dissolving under
    /// the Oracle's control, writes a create-only `.reconciled.json`. Never submits an update.
    Reconcile {
        #[arg(long)]
        neuron_id: u64,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        owner_pem: PathBuf,
        #[arg(long, default_value=DEFAULT_SIGNING)]
        signing: String,
        #[arg(long, default_value=DEFAULT_GOVERNANCE)]
        governance: String,
        #[arg(long, default_value=DEFAULT_OWNER)]
        owner_principal: String,
        #[arg(long, default_value=identity::HISTORICAL_ORACLE_PRINCIPAL)]
        expected: String,
        #[arg(long, default_value=DEFAULT_IC_URL)]
        ic_url: String,
        #[arg(long, default_value = "audit-out")]
        out_dir: PathBuf,
    },
    Batch {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        owner_pem: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        confirm_batch: bool,
        #[arg(long, default_value=DEFAULT_SIGNING)]
        signing: String,
        #[arg(long, default_value=DEFAULT_GOVERNANCE)]
        governance: String,
        #[arg(long, default_value=DEFAULT_OWNER)]
        owner_principal: String,
        #[arg(long, default_value=identity::HISTORICAL_ORACLE_PRINCIPAL)]
        expected: String,
        #[arg(long, default_value=DEFAULT_IC_URL)]
        ic_url: String,
        #[arg(long, default_value = "audit-out")]
        out_dir: PathBuf,
    },
}

fn parse_batch_size(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if (1..=25).contains(&n) => Ok(n),
        _ => Err("batch size must be an integer in 1..=25".into()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn run() -> Result<bool> {
    match Cli::parse().command {
        Command::Identity {
            signing,
            expected,
            ic_url,
        } => identity_cmd(signing, expected, ic_url).await,
        Command::Inspect {
            neuron_id,
            confirm_signing,
            max_signatures,
            net,
        } => inspect(neuron_id, confirm_signing, max_signatures, net).await,
        Command::Inventory {
            command:
                Some(InventoryCommand::Sync {
                    input_dir,
                    out,
                    include_history,
                    sources,
                    report,
                    dry_run,
                }),
            ..
        } => {
            let crate_dir = sync::crate_dir();
            let out = out.unwrap_or_else(|| {
                input_dir
                    .unwrap_or_else(|| crate_dir.join("audit-in"))
                    .join("neurons.txt")
            });
            let mut extra = Vec::new();
            for s in sources {
                let (k, p) = s.split_once('=').context("--source must be KIND=PATH")?;
                extra.push((PathBuf::from(p), sync::Kind::parse(k)?));
            }
            sync::sync(&sync::SyncArgs {
                out,
                report: Some(
                    report.unwrap_or_else(|| crate_dir.join("audit-out/inventory-report.md")),
                ),
                include_history,
                sources: extra,
                crate_dir,
                dry_run,
            })?;
            Ok(true)
        }
        Command::Inventory {
            command: None,
            ids_file,
            batch_size,
        } => {
            let ids_file = ids_file.context("--ids-file is required (or use `inventory sync`)")?;
            let inv = load_inventory(&ids_file)?;
            let plan = audit::plan(&inv.ids, batch_size);
            print_plan(&plan);
            Ok(true)
        }
        Command::Audit {
            ids_file,
            batch_size,
            max_signatures,
            confirm_signing,
            net,
            opts,
        } => {
            audit_cmd(
                ids_file,
                batch_size,
                max_signatures,
                confirm_signing,
                net,
                opts,
            )
            .await
        }
        Command::RecoverDisburse(a) => recovery::run(*a).await,
        Command::Control { ctl } => {
            write_control(&ctl)?;
            Ok(true)
        }
        Command::Probe {
            max_signatures,
            confirm_signing,
            net,
            ctl,
        } => probe_cmd(max_signatures, confirm_signing, net, ctl).await,
        Command::Report { opts } => {
            write_reports(&opts)?;
            Ok(true)
        }
        Command::Deposit { command } => deposit::run(command).await,
        Command::Dissolve { command } => dissolve_cmd(command).await,
    }
}

async fn dissolve_cmd(c: DissolveCommand) -> Result<bool> {
    match c {
        DissolveCommand::Plan {
            ids_file,
            out_dir,
            owner_pem,
            signing,
            governance,
            owner_principal,
            expected,
            ic_url,
        } => {
            let ids_file = ids_file.unwrap_or_else(sync::default_ids_file);
            let inv = load_inventory(&ids_file)?;
            let signing = Principal::from_text(&signing)?;
            let gov = Principal::from_text(&governance)?;
            let owner = Principal::from_text(&owner_principal)?;
            let expected = Principal::from_text(&expected)?;
            let p = session::preflight(&owner_pem, owner, signing, &ic_url).await?;
            let planned_signatures = (inv.ids.len().div_ceil(25) + 2) as u32;
            anyhow::ensure!(
                planned_signatures <= AUDIT_MAX_SIGNATURES,
                "inventory exceeds dissolution planner signature ceiling ({AUDIT_MAX_SIGNATURES})"
            );
            let s = session::connect_oracle(p, signing, gov, expected, &ic_url, planned_signatures)
                .await?;
            let mut records = Vec::new();
            for batch in inv.ids.chunks(25) {
                let b = s
                    .agent
                    .query(&gov, "list_neurons")
                    .with_arg(governance::encode_list_neurons_batch(batch)?)
                    .call()
                    .await?;
                let resp = governance::decode_list_neurons(&b)?;
                for id in batch {
                    let full = resp
                        .full_neurons
                        .iter()
                        .find(|n| n.id.as_ref().map(|x| x.id) == Some(*id));
                    let info = resp
                        .neuron_infos
                        .iter()
                        .find(|(i, _)| i == id)
                        .map(|(_, x)| x);
                    records.push(snapshot::NeuronRecord::from_response(
                        *id,
                        full,
                        info,
                        &s.principal,
                    ));
                }
            }
            let plan = dissolve::make_plan(
                &inv.ids,
                &records,
                &s.principal,
                &gov.to_text(),
                &ids_file.display().to_string(),
                &inv.source_sha256,
                now_unix(),
            );
            std::fs::create_dir_all(out_dir.join("dissolve"))?;
            let path = out_dir.join("dissolve").join(format!(
                "plan-{}.json",
                governance::fmt_compact_utc(now_unix())
            ));
            dissolve::write_plan(&path, &plan)?;
            println!(
                "Fresh plan: {} eligible, {} excluded; sha256 {}",
                plan.eligible.len(),
                plan.excluded.len(),
                plan.plan_sha256
            );
            println!("{}", path.display());
            Ok(true)
        }
        DissolveCommand::Start {
            neuron_id,
            plan,
            owner_pem,
            execute,
            signing,
            governance,
            owner_principal,
            expected,
            ic_url,
            out_dir,
        } => {
            run_start(
                neuron_id,
                plan,
                owner_pem,
                execute,
                signing,
                governance,
                owner_principal,
                expected,
                ic_url,
                out_dir,
            )
            .await
        }
        DissolveCommand::Reconcile {
            neuron_id,
            plan,
            owner_pem,
            signing,
            governance,
            owner_principal,
            expected,
            ic_url,
            out_dir,
        } => {
            let p = dissolve::load_plan(&plan)?;
            let gov = Principal::from_text(&governance)?;
            let signing = Principal::from_text(&signing)?;
            let owner = Principal::from_text(&owner_principal)?;
            let expected = Principal::from_text(&expected)?;
            anyhow::ensure!(p.governance == gov.to_text(), "plan Governance mismatch");
            anyhow::ensure!(
                p.oracle_principal == expected.to_text(),
                "plan Oracle mismatch"
            );
            let dir = out_dir.join("dissolve").join("journal");
            let prefix = format!("{}-{neuron_id}", p.plan_sha256);
            let result_path = dir.join(format!("{prefix}.result.json"));
            let rec_path = dir.join(format!("{prefix}.reconciled.json"));
            anyhow::ensure!(
                !rec_path.exists(),
                "already reconciled: {}",
                rec_path.display()
            );
            let prior: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&result_path)
                    .with_context(|| format!("no result record {}", result_path.display()))?,
            )?;
            anyhow::ensure!(
                dissolve::is_reconcilable(&prior),
                "journal result is not the known mis-classification; refusing to reconcile automatically"
            );
            let pre = session::preflight(&owner_pem, owner, signing, &ic_url).await?;
            let s = session::connect_oracle(pre, signing, gov, expected, &ic_url, 3).await?;
            let after = read_fresh_neuron(&s.agent, &gov, neuron_id, &s.principal).await?;
            let when = match after.dissolve {
                Some(snapshot::DissolveRec::WhenDissolvedTimestampSeconds(t))
                    if after.access == governance::Access::Controller =>
                {
                    t
                }
                _ => bail!(
                    "fresh state does not show a controlled, dissolving neuron; not reconciling"
                ),
            };
            dissolve::write_record(
                &rec_path,
                &serde_json::json!({"outcome":"verified_success","reconciled":true,"neuron_id":neuron_id.to_string(),"original_result":prior,"dissolving_until_unix":when,"verified_at_unix":now_unix(),"note":"original record mis-classified by response decoder bug (Configure : record {}); state verified by fresh signed read"}),
            )?;
            println!(
                "Reconciled neuron {neuron_id}: dissolving until {when}; wrote {}",
                rec_path.display()
            );
            Ok(true)
        }
        DissolveCommand::Batch {
            plan,
            owner_pem,
            execute,
            confirm_batch,
            signing,
            governance,
            owner_principal,
            expected,
            ic_url,
            out_dir,
        } => {
            if !execute {
                bail!("batch is prepare-only unless --execute is supplied");
            }
            if !confirm_batch {
                bail!("batch execution requires --confirm-batch");
            }
            if owner_pem == Path::new("-") {
                bail!("batch requires a PEM file; stdin cannot be replayed across sequential fresh preflights");
            }
            let p = dissolve::load_plan(&plan)?;
            let mut completed = 0usize;
            for e in p.eligible {
                let ok = run_start(
                    e.neuron_id.parse()?,
                    plan.clone(),
                    owner_pem.clone(),
                    true,
                    signing.clone(),
                    governance.clone(),
                    owner_principal.clone(),
                    expected.clone(),
                    ic_url.clone(),
                    out_dir.clone(),
                )
                .await?;
                if !ok {
                    bail!("batch stopped after non-successful neuron {}; inspect journal before resuming",e.neuron_id);
                }
                completed += 1;
            }
            println!("Batch summary: {completed} verified or safely skipped; remaining operations are journaled or unattempted");
            Ok(true)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_start(
    id: u64,
    plan_path: PathBuf,
    pem: PathBuf,
    execute: bool,
    signing_s: String,
    gov_s: String,
    owner_s: String,
    expected_s: String,
    url: String,
    out: PathBuf,
) -> Result<bool> {
    if !execute {
        println!("DRY RUN: no update submitted for neuron {id}");
        return Ok(true);
    }
    let p = dissolve::load_plan(&plan_path)?;
    p.eligible
        .iter()
        .find(|e| e.neuron_id == id.to_string())
        .ok_or_else(|| anyhow!("neuron {id} is not eligible in reviewed plan"))?;
    let gov = Principal::from_text(&gov_s)?;
    let signing = Principal::from_text(&signing_s)?;
    let owner = Principal::from_text(&owner_s)?;
    let expected = Principal::from_text(&expected_s)?;
    anyhow::ensure!(p.governance == gov.to_text(), "plan Governance mismatch");
    anyhow::ensure!(
        p.oracle_principal == expected.to_text(),
        "plan Oracle mismatch"
    );
    let dir = out.join("dissolve").join("journal");
    std::fs::create_dir_all(&dir)?;
    let prefix = format!("{}-{id}", p.plan_sha256);
    let intent = dir.join(format!("{prefix}.intent.json"));
    let result_path = dir.join(format!("{prefix}.result.json"));
    if dir.join(format!("{prefix}.reconciled.json")).exists() {
        println!("SKIP neuron {id}: reconciled as verified success");
        return Ok(true);
    }
    if result_path.exists() {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&result_path)?)?;
        if v["outcome"] == "verified_success"
            || v["outcome"] == "skipped_already_started_or_dissolved"
        {
            println!("SKIP neuron {id}: prior result verified success");
            return Ok(true);
        }
        bail!("prior attempt exists for neuron {id}; reconcile it manually; refusing repeat");
    }
    if intent.exists() {
        bail!("prior intent exists for neuron {id} without final result; reconcile before retry");
    }
    let payload = dissolve::encode_start_dissolving(id)?;
    let pre = session::preflight(&pem, owner, signing, &url).await?;
    let s =
        session::connect_oracle_for_dissolve(pre, signing, gov, expected, &url, 8, payload.clone())
            .await?;
    let before = read_fresh_neuron(&s.agent, &gov, id, &s.principal).await?;
    anyhow::ensure!(
        before.access == governance::Access::Controller,
        "fresh state does not prove controller authority"
    );
    if matches!(
        before.dissolve,
        Some(snapshot::DissolveRec::WhenDissolvedTimestampSeconds(_))
            | Some(snapshot::DissolveRec::DelaySeconds(0))
    ) {
        dissolve::write_record(
            &result_path,
            &serde_json::json!({"outcome":"skipped_already_started_or_dissolved","neuron_id":id.to_string(),"verified_at_unix":now_unix()}),
        )?;
        println!("SKIP neuron {id}: already dissolving or dissolved");
        return Ok(true);
    }
    anyhow::ensure!(
        matches!(before.dissolve,Some(snapshot::DissolveRec::DelaySeconds(d)) if d>0),
        "fresh state is not locked and eligible"
    );
    let started = now_unix();
    dissolve::write_record(
        &intent,
        &serde_json::json!({"status":"submitting","run_id":p.plan_sha256,"neuron_id":id.to_string(),"submitted_at_unix":started,"payload_sha256":dissolve::hex(&sha2::Sha256::digest(&payload)),"previous_state":"locked","note":"intent is write-once; ambiguous outcomes must be reconciled, never retried blindly"}),
    )?;
    let response = s
        .agent
        .update(&gov, "manage_neuron")
        .with_arg(payload)
        .call_and_wait()
        .await;
    let (governance_result, submission_error) = match response {
        Ok(b) => match dissolve::decode_response(&b) {
            Ok(result) => (result, None),
            Err(e) => (
                Err(format!("response decode failure: {e}")),
                Some(format!("response decode failure: {e}")),
            ),
        },
        Err(e) => (
            Err(format!("ambiguous transport outcome: {e}")),
            Some(format!("ambiguous transport outcome: {e}")),
        ),
    };
    let after = read_fresh_neuron(&s.agent, &gov, id, &s.principal).await;
    let state = after.as_ref().ok().and_then(|r| match r.dissolve {
        Some(snapshot::DissolveRec::WhenDissolvedTimestampSeconds(t))
            if r.access == governance::Access::Controller =>
        {
            Some(t)
        }
        _ => None,
    });
    let outcome = dissolve::submission_outcome(
        submission_error.is_some(),
        governance_result.is_ok(),
        state.is_some(),
    );
    dissolve::write_record(
        &result_path,
        &serde_json::json!({"outcome":outcome,"neuron_id":id.to_string(),"submitted_at_unix":started,"governance_result":governance_result.as_ref().map(|_|"accepted").unwrap_or_else(|e|e.as_str()),"submission_error":submission_error,"resulting_state":state.map(|t|format!("dissolving until {t}")),"verification_error":after.err().map(|e|e.to_string())}),
    )?;
    if outcome == "unknown" {
        bail!("operation outcome unknown; intent recorded; do not retry");
    }
    println!("Neuron {id}: {outcome}; intent {}", intent.display());
    Ok(outcome == "verified_success")
}

async fn read_fresh_neuron(
    agent: &Agent,
    gov: &Principal,
    id: u64,
    oracle: &Principal,
) -> Result<snapshot::NeuronRecord> {
    let b = agent
        .query(gov, "list_neurons")
        .with_arg(governance::encode_list_neurons(id)?)
        .call()
        .await?;
    let r = governance::decode_list_neurons(&b)?;
    let full = r
        .full_neurons
        .iter()
        .find(|n| n.id.as_ref().map(|i| i.id) == Some(id));
    let info = r
        .neuron_infos
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, n)| n);
    Ok(snapshot::NeuronRecord::from_response(
        id, full, info, oracle,
    ))
}

async fn identity_cmd(signing: String, expected: String, ic_url: String) -> Result<bool> {
    let signing = Principal::from_text(&signing).context("invalid --signing principal")?;
    let expected = Principal::from_text(&expected).context("invalid --expected principal")?;

    // Anonymous agent: no local key is loaded or needed.
    let agent = Agent::builder().with_url(ic_url).build()?;
    let reply = agent
        .update(&signing, "public_key")
        .with_arg(candid::encode_args(())?)
        .call_and_wait()
        .await
        .context("public_key call failed")?;

    let sec1 = identity::decode_public_key_reply(&reply).map_err(|e| anyhow!(e))?;
    let der = identity::sec1_to_spki_der(&sec1).map_err(|e| anyhow!(e))?;
    let derived = Principal::self_authenticating(&der);

    println!("Signing canister : {signing}");
    println!("SEC1 public key  : {}", hex(&sec1));
    println!("SPKI DER (hex)   : {}", hex(&der));
    println!("Derived principal: {derived}");
    println!("Expected         : {expected}");
    if derived == expected {
        println!("RESULT: MATCH");
        Ok(true)
    } else {
        println!("RESULT: MISMATCH");
        Ok(false)
    }
}

async fn inspect(
    neuron_id: u64,
    confirm_signing: bool,
    max_signatures: u32,
    net: Net,
) -> Result<bool> {
    let signing = Principal::from_text(&net.signing).context("invalid --signing")?;
    let governance = Principal::from_text(&net.governance).context("invalid --governance")?;
    let owner_principal =
        Principal::from_text(&net.owner_principal).context("invalid --owner-principal")?;
    let expected = Principal::from_text(&net.expected).context("invalid --expected")?;
    let max_signatures = max_signatures.min(INSPECT_MAX_SIGNATURES);

    let pre = session::preflight(&net.owner_pem, owner_principal, signing, &net.ic_url).await?;

    if !confirm_signing {
        println!();
        println!("DRY RUN: no signing performed. With --confirm-signing this will:");
        println!("  1. call signing.public_key and require it to derive {expected}");
        println!("  2. send one signed Governance.list_neurons QUERY for neuron {neuron_id}");
        println!("     (up to {max_signatures} signing.sign update calls, each paid in cycles by the signing canister)");
        println!(
            "  Nothing else is ever signed: update calls and other methods are refused in code."
        );
        return Ok(true);
    }

    let s = session::connect_oracle(
        pre,
        signing,
        governance,
        expected,
        &net.ic_url,
        max_signatures,
    )
    .await?;
    let response = s
        .agent
        .query(&governance, "list_neurons")
        .with_arg(governance::encode_list_neurons(neuron_id)?)
        .call()
        .await
        .context("Governance.list_neurons query failed")?;
    println!("Signatures used  : {}", s.identity.signatures_used());
    let result = governance::decode_list_neurons(&response)?;
    print_neuron_report(
        neuron_id,
        &result,
        &s.principal,
        signing,
        Principal::from_text(DEFAULT_DEPOSITS)?,
    );
    Ok(true)
}

fn load_inventory(path: &Path) -> Result<inventory::Inventory> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let inv = inventory::parse_ids(&text);
    println!("Inventory file   : {}", path.display());
    println!("IDs as written   : {}", inv.original_count);
    println!("Unique IDs       : {}", inv.ids.len());
    println!("Duplicates       : {}", inv.duplicates());
    println!(
        "Ignored lines    : {} (non-ID lines such as shell code)",
        inv.ignored_lines
    );
    if inv.ids.is_empty() {
        bail!("no neuron IDs found in {}", path.display());
    }
    Ok(inv)
}

fn print_plan(plan: &audit::Plan) {
    println!("Batches          : {}", plan.batches.len());
    println!(
        "Signatures needed: {} ({} batches + {} read_state reserve)",
        plan.required_signatures,
        plan.batches.len(),
        audit::READ_STATE_OVERHEAD
    );
    println!(
        "Max cost         : {} cycles charged to the signing canister (~{} per signature)",
        plan.required_signatures as u64 * audit::CYCLES_PER_SIGNATURE,
        audit::CYCLES_PER_SIGNATURE
    );
}

async fn audit_cmd(
    ids_file: PathBuf,
    batch_size: usize,
    max_signatures: u32,
    confirm_signing: bool,
    net: Net,
    opts: ReportOpts,
) -> Result<bool> {
    let signing = Principal::from_text(&net.signing).context("invalid --signing")?;
    let governance = Principal::from_text(&net.governance).context("invalid --governance")?;
    let owner_principal =
        Principal::from_text(&net.owner_principal).context("invalid --owner-principal")?;
    let expected = Principal::from_text(&net.expected).context("invalid --expected")?;

    // Everything up to the preflight is offline.
    let inv = load_inventory(&ids_file)?;
    let plan = audit::plan(&inv.ids, batch_size);
    print_plan(&plan);
    println!("Signature budget : {max_signatures}");
    audit::check_budget(&plan, max_signatures)?;

    let pre = session::preflight(&net.owner_pem, owner_principal, signing, &net.ic_url).await?;

    if !confirm_signing {
        println!();
        println!("DRY RUN: no signing performed. With --confirm-signing this will:");
        println!("  1. call signing.public_key and require it to derive {expected}");
        println!("  2. send {} signed Governance.list_neurons QUERIES ({} IDs, batches of up to {batch_size})", plan.batches.len(), inv.ids.len());
        println!(
            "  3. write an immutable snapshot and reports under {}",
            opts.out_dir.display()
        );
        println!("  Hard cap: {max_signatures} signatures; update calls and other methods are refused in code.");
        return Ok(true);
    }

    // Fail before spending anything if the output location is unusable.
    std::fs::create_dir_all(snapshot::snapshots_dir(&opts.out_dir))
        .with_context(|| format!("cannot create {}", opts.out_dir.display()))?;

    let s = session::connect_oracle(
        pre,
        signing,
        governance,
        expected,
        &net.ic_url,
        max_signatures,
    )
    .await?;
    let agent = &s.agent;
    let fetch = |ids: Vec<u64>| async move {
        let arg = governance::encode_list_neurons_batch(&ids).map_err(|e| e.to_string())?;
        let bytes = agent
            .query(&governance, "list_neurons")
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| format!("Governance.list_neurons query failed: {e}"))?;
        governance::decode_list_neurons(&bytes)
            .map_err(|e| format!("cannot decode list_neurons response: {e}"))
    };
    let collected = audit::collect(&plan.batches, &s.principal, fetch).await;

    let snap = snapshot::Snapshot {
        schema_version: snapshot::SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        taken_at_unix: now_unix(),
        governance: governance.to_text(),
        signing_canister: signing.to_text(),
        oracle_principal: s.principal.to_text(),
        inventory: snapshot::InventoryMeta {
            source: ids_file.display().to_string(),
            source_sha256: inv.source_sha256.clone(),
            original_count: inv.original_count,
            unique_count: inv.ids.len(),
        },
        query: snapshot::QueryMeta {
            batch_size,
            batches_planned: plan.batches.len(),
            batches_completed: collected.batches_completed,
            signature_budget: max_signatures,
            signatures_used: s.identity.signatures_used().min(max_signatures),
            complete: collected.complete,
        },
        neurons: collected.records,
    };
    let path = snapshot::write_snapshot(&opts.out_dir, &snap)?;
    println!("Snapshot written : {} (read-only)", path.display());
    println!("Signatures used  : {}", snap.query.signatures_used);
    let by = |st: snapshot::Status| snap.neurons.iter().filter(|r| r.status == st).count();
    println!(
        "Neurons          : {} full, {} info_only, {} not_found, {} query_failed, {} not_queried",
        by(snapshot::Status::Full),
        by(snapshot::Status::InfoOnly),
        by(snapshot::Status::NotFound),
        by(snapshot::Status::QueryFailed),
        by(snapshot::Status::NotQueried)
    );
    write_reports(&opts)?;
    if !collected_complete(&snap) {
        println!("WARNING: audit INCOMPLETE; see query_failed / not_queried neurons.");
    }
    Ok(collected_complete(&snap))
}

fn collected_complete(s: &snapshot::Snapshot) -> bool {
    s.query.complete
}

/// Regenerates `neurons-latest.csv` and `summary-latest.md` from the saved snapshots.
fn write_reports(opts: &ReportOpts) -> Result<()> {
    let loaded = snapshot::load_snapshots(&opts.out_dir)?;
    let Some((_, latest)) = loaded.last() else {
        bail!(
            "no snapshots found in {}",
            snapshot::snapshots_dir(&opts.out_dir).display()
        );
    };
    let refs: Vec<&snapshot::Snapshot> = loaded.iter().map(|(_, s)| s).collect();
    let h = history::analyze(&refs, opts.min_interval_secs, opts.protocol_share_bps);
    let csv_path = opts.out_dir.join("neurons-latest.csv");
    let md_path = opts.out_dir.join("summary-latest.md");
    std::fs::write(&csv_path, report::csv(latest))?;
    std::fs::write(&md_path, report::markdown(latest, &h))?;
    println!("Snapshots loaded : {}", loaded.len());
    println!("CSV              : {}", csv_path.display());
    println!("Summary          : {}", md_path.display());
    if let Some(msg) = &h.insufficient {
        println!("History          : {msg}");
    }
    Ok(())
}

fn print_neuron_report(
    neuron_id: u64,
    r: &governance::ListNeuronsResponse,
    oracle: &Principal,
    signing: Principal,
    deposits: Principal,
) {
    use governance::*;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!();
    println!("=== Neuron {neuron_id} ===");
    if let Some((_, info)) = r.neuron_infos.iter().find(|(id, _)| *id == neuron_id) {
        println!(
            "Public info      : state {} ({}), stake {} ICP, dissolve delay {}s, voting power {}",
            info.state,
            state_name(info.state),
            fmt_icp(info.stake_e8s),
            info.dissolve_delay_seconds,
            info.voting_power
        );
    } else {
        println!("Public info      : none returned (neuron may not exist)");
    }
    let neuron = r
        .full_neurons
        .iter()
        .find(|n| n.id.as_ref().map(|i| i.id) == Some(neuron_id));
    let Some(n) = neuron else {
        println!(
            "Full neuron      : NOT READABLE by the Oracle principal (no controller/hotkey access)"
        );
        println!("Access           : {:?}", classify(None, oracle));
        return;
    };
    let label = |p: &Principal| {
        if p == oracle {
            format!("{p}  <- Oracle ECDSA principal")
        } else if *p == signing {
            format!("{p}  <- signing canister id")
        } else if *p == deposits {
            format!("{p}  <- deposits canister")
        } else {
            p.to_text()
        }
    };
    println!(
        "Controller       : {}",
        n.controller
            .as_ref()
            .map(label)
            .unwrap_or_else(|| "none".into())
    );
    if n.hot_keys.is_empty() {
        println!("Hotkeys          : none");
    }
    for h in &n.hot_keys {
        println!("Hotkey           : {}", label(h));
    }
    println!(
        "Cached stake     : {} ICP",
        fmt_icp(n.cached_neuron_stake_e8s)
    );
    println!("Neuron fees      : {} ICP", fmt_icp(n.neuron_fees_e8s));
    println!(
        "Maturity         : {} ICP-equivalent (current balance, not lifetime rewards)",
        fmt_icp(n.maturity_e8s_equivalent)
    );
    match n.staked_maturity_e8s_equivalent {
        Some(v) => println!("Staked maturity  : {} ICP-equivalent", fmt_icp(v)),
        None => println!("Staked maturity  : none reported"),
    }
    println!("Auto-stake mat.  : {:?}", n.auto_stake_maturity);
    println!(
        "Dissolve state   : {}",
        describe_dissolve(&n.dissolve_state, now)
    );
    if let Some(t) = n.spawn_at_timestamp_seconds {
        println!("Spawning at      : {}", fmt_utc(t));
    }
    println!(
        "Created          : {}",
        fmt_utc(n.created_timestamp_seconds)
    );
    println!();
    match classify(Some(n), oracle) {
        Access::Controller => println!(
            "ACCESS: CONTROLLER. The Oracle principal controls this neuron (manage_neuron authority exists).\n\
             Disbursement additionally requires the neuron to be dissolved; none was attempted."
        ),
        Access::HotKeyOnly => println!(
            "ACCESS: HOTKEY ONLY. Readable and can vote/follow, but CANNOT dissolve, split or disburse."
        ),
        Access::ReadableWithoutAuthority => println!(
            "ACCESS: READABLE ONLY. Oracle is neither controller nor hotkey; no authority over this neuron."
        ),
        Access::NotReadable => println!("ACCESS: NOT READABLE."),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load_baseline(ctl: &ControlOpts) -> Result<(PathBuf, snapshot::Snapshot)> {
    if let Some(p) = &ctl.snapshot {
        let s: snapshot::Snapshot = serde_json::from_slice(
            &std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?,
        )?;
        if s.schema_version != snapshot::SCHEMA_VERSION {
            bail!("unsupported snapshot schema {}", s.schema_version);
        }
        return Ok((p.clone(), s));
    }
    let mut all = snapshot::load_snapshots(&ctl.out_dir)?;
    all.pop().ok_or_else(|| {
        anyhow!(
            "no snapshots in {}; run `audit` first",
            snapshot::snapshots_dir(&ctl.out_dir).display()
        )
    })
}

fn known_principals(ctl: &ControlOpts, oracle: &str) -> Result<Vec<control::KnownPrincipal>> {
    let mut v = vec![
        (
            "oracle (signing-canister ECDSA identity)",
            oracle.to_string(),
        ),
        ("deposits canister", ctl.deposits.clone()),
        ("signing canister", ctl.signing_canister.clone()),
        ("local owner (sticpowner)", ctl.local_owner.clone()),
        ("NNS Governance", DEFAULT_GOVERNANCE.to_string()),
    ]
    .into_iter()
    .map(|(l, p)| (l.to_string(), p))
    .collect::<Vec<_>>();
    for k in &ctl.known {
        let (l, p) = k
            .split_once('=')
            .ok_or_else(|| anyhow!("--known expects LABEL=PRINCIPAL, got {k:?}"))?;
        v.push((l.to_string(), p.to_string()));
    }
    v.into_iter()
        .map(|(label, principal)| {
            Principal::from_text(&principal)
                .with_context(|| format!("invalid principal for {label}"))?;
            Ok(control::KnownPrincipal { label, principal })
        })
        .collect()
}

fn write_control(ctl: &ControlOpts) -> Result<()> {
    let (base_path, base) = load_baseline(ctl)?;
    let probe = control::load_latest_probe(&ctl.out_dir)?;
    let known = known_principals(ctl, &base.oracle_principal)?;
    let report = control::build(&base, probe.as_ref().map(|(_, p)| p), known);
    let reproduce = "dfx identity export sticpowner | cargo run --locked -- probe --owner-pem - --max-signatures 31 --out-dir audit-out --confirm-signing\ncargo run --locked -- control --out-dir audit-out";
    let md = ctl.out_dir.join("control-report.md");
    let js = ctl.out_dir.join("control-report.json");
    std::fs::write(&md, control::markdown(&report, reproduce))?;
    std::fs::write(&js, serde_json::to_vec_pretty(&report)?)?;
    println!("Baseline         : {}", base_path.display());
    match &probe {
        Some((p, _)) => println!("Probe            : {}", p.display()),
        None => println!("Probe            : none (all non-full neurons stay `unknown`)"),
    }
    for (c, b) in &report.by_class {
        println!(
            "{:<21}: {:>3} neurons, {} ICP net stake",
            c.name(),
            b.neurons,
            governance::fmt_e8s(b.net_stake_e8s)
        );
    }
    println!(
        "StartDissolving eligible (NOT executed): {}",
        report.eligible_for_start_dissolving.len()
    );
    println!("Report           : {}", md.display());
    println!("JSON             : {}", js.display());
    Ok(())
}

async fn probe_cmd(
    max_signatures: u32,
    confirm_signing: bool,
    net: Net,
    ctl: ControlOpts,
) -> Result<bool> {
    let signing = Principal::from_text(&net.signing).context("invalid --signing")?;
    let governance = Principal::from_text(&net.governance).context("invalid --governance")?;
    let owner_principal =
        Principal::from_text(&net.owner_principal).context("invalid --owner-principal")?;
    let expected = Principal::from_text(&net.expected).context("invalid --expected")?;

    let (base_path, base) = load_baseline(&ctl)?;
    let ids: Vec<u64> = base
        .neurons
        .iter()
        .filter(|r| r.status == snapshot::Status::InfoOnly)
        .filter_map(|r| r.id())
        .collect();
    println!("Baseline         : {}", base_path.display());
    println!("Neurons to probe : {} (info_only in baseline)", ids.len());
    let needed = ids.len() as u32 + audit::READ_STATE_OVERHEAD;
    println!(
        "Signatures needed: {needed} (one get_full_neuron query each + {} read_state reserve)",
        audit::READ_STATE_OVERHEAD
    );
    println!("Signature budget : {max_signatures}");
    if ids.is_empty() {
        bail!("baseline has no info_only neurons; nothing to probe");
    }
    if needed > max_signatures {
        bail!("budget too small: need {needed} signatures, --max-signatures is {max_signatures}");
    }
    println!(
        "Max cost         : {} cycles charged to the signing canister",
        u64::from(needed) * audit::CYCLES_PER_SIGNATURE
    );
    let pre = session::preflight(&net.owner_pem, owner_principal, signing, &net.ic_url).await?;
    if !confirm_signing {
        println!();
        println!(
            "DRY RUN: no signing performed. With --confirm-signing this will send up to {} signed",
            ids.len()
        );
        println!(
            "Governance.get_full_neuron QUERIES (read-only) and save a probe file under {}.",
            ctl.out_dir.display()
        );
        return Ok(true);
    }
    std::fs::create_dir_all(control::probes_dir(&ctl.out_dir))?;
    let s = session::connect_oracle(
        pre,
        signing,
        governance,
        expected,
        &net.ic_url,
        max_signatures,
    )
    .await?;
    if s.principal.to_text() != base.oracle_principal {
        bail!("live Oracle principal differs from the baseline snapshot's; aborting");
    }

    let mut results = vec![];
    let mut aborted = false;
    for id in &ids {
        let neuron_id = id.to_string();
        if aborted {
            results.push(control::ProbeResult {
                neuron_id,
                outcome: control::ProbeOutcome::NotProbed,
            });
            continue;
        }
        let call = s
            .agent
            .query(&governance, "get_full_neuron")
            .with_arg(governance::encode_get_full_neuron(*id)?)
            .call()
            .await;
        let outcome = match call {
            Err(e) => {
                aborted = true;
                control::ProbeOutcome::CallFailed {
                    message: e.to_string(),
                }
            }
            Ok(bytes) => match governance::decode_get_full_neuron(&bytes) {
                Err(e) => {
                    aborted = true;
                    control::ProbeOutcome::CallFailed {
                        message: format!("decode error: {e}"),
                    }
                }
                Ok(governance::FullNeuronResult::Err(e)) => control::ProbeOutcome::Refused {
                    error_type: e.error_type,
                    message: e.error_message,
                },
                Ok(governance::FullNeuronResult::Ok(n)) => {
                    // Keep the baseline's public info alongside the full record.
                    let info = base.neurons.iter().find(|r| r.neuron_id == neuron_id);
                    let mut rec =
                        snapshot::NeuronRecord::from_response(*id, Some(&n), None, &s.principal);
                    if let Some(i) = info {
                        rec.info_state = i.info_state;
                        rec.info_stake_e8s = i.info_stake_e8s;
                        rec.info_dissolve_delay_seconds = i.info_dissolve_delay_seconds;
                    }
                    control::ProbeOutcome::Full {
                        record: Box::new(rec),
                    }
                }
            },
        };
        results.push(control::ProbeResult { neuron_id, outcome });
    }
    let used = s.identity.signatures_used().min(max_signatures);
    let pf = control::ProbeFile {
        schema_version: control::PROBE_SCHEMA_VERSION,
        taken_at_unix: now_unix(),
        oracle_principal: s.principal.to_text(),
        governance: governance.to_text(),
        method: "get_full_neuron".into(),
        signature_budget: max_signatures,
        signatures_used: used,
        results,
    };
    let path = control::write_probe(&ctl.out_dir, &pf)?;
    println!("Probe written    : {} (read-only)", path.display());
    println!("Signatures used  : {used}");
    let count =
        |f: fn(&control::ProbeOutcome) -> bool| pf.results.iter().filter(|r| f(&r.outcome)).count();
    println!(
        "Results          : {} full, {} refused, {} call_failed, {} not_probed",
        count(|o| matches!(o, control::ProbeOutcome::Full { .. })),
        count(|o| matches!(o, control::ProbeOutcome::Refused { .. })),
        count(|o| matches!(o, control::ProbeOutcome::CallFailed { .. })),
        count(|o| matches!(o, control::ProbeOutcome::NotProbed))
    );
    write_control(&ctl)?;
    Ok(!aborted)
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn plan_ids_file_is_optional_and_override_preserved() {
        let base = ["neuron-audit", "dissolve", "plan", "--owner-pem", "x.pem"];
        let c = Cli::try_parse_from(base).unwrap();
        let Command::Dissolve {
            command: DissolveCommand::Plan { ids_file, .. },
        } = c.command
        else {
            panic!()
        };
        assert!(ids_file.is_none());
        let c = Cli::try_parse_from([&base[..], &["--ids-file", "my.txt"]].concat()).unwrap();
        let Command::Dissolve {
            command: DissolveCommand::Plan { ids_file, .. },
        } = c.command
        else {
            panic!()
        };
        assert_eq!(ids_file, Some(PathBuf::from("my.txt")));
    }

    #[test]
    fn legacy_inventory_and_sync_parse() {
        assert!(Cli::try_parse_from(["neuron-audit", "inventory", "--ids-file", "a"]).is_ok());
        assert!(
            Cli::try_parse_from(["neuron-audit", "inventory", "sync", "--include-history"]).is_ok()
        );
    }
}
