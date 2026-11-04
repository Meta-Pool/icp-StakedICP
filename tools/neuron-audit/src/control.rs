//! Control reconciliation: which neurons does the Oracle verifiably control?
//!
//! Evidence rules (nothing here is inferred from public `neuron_info`):
//! * `list_neurons` / `get_full_neuron` return a neuron's controller and hotkeys only to callers
//!   Governance deems authorized (controller or hotkey) or when the neuron is publicly visible.
//! * An `info_only` neuron therefore proves one thing: Governance did not show us the full record.
//!   It does NOT prove the neuron has another controller, nor that it is missing.
//! * Only a full record can establish `confirmed_controller`, `confirmed_hotkey` or
//!   `other_controller`. Everything else is `unknown`.

use crate::governance::{fmt_e8s, fmt_utc};
use crate::snapshot::{dissolve_class, DissolveClass, NeuronRecord, Snapshot, Status};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const PROBE_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// `get_full_neuron` returned the full record.
    Full { record: Box<NeuronRecord> },
    /// Governance answered with an error (typically not authorized).
    Refused { error_type: i32, message: String },
    /// Transport/decoding failure; says nothing about the neuron.
    CallFailed { message: String },
    /// Not attempted (budget exhausted or earlier transport failure).
    NotProbed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProbeResult {
    pub neuron_id: String,
    #[serde(flatten)]
    pub outcome: ProbeOutcome,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProbeFile {
    pub schema_version: u32,
    pub taken_at_unix: u64,
    pub oracle_principal: String,
    pub governance: String,
    pub method: String,
    pub signature_budget: u32,
    pub signatures_used: u32,
    pub results: Vec<ProbeResult>,
}

pub fn probes_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("probes")
}

pub fn write_probe(out_dir: &Path, p: &ProbeFile) -> Result<PathBuf> {
    let dir = probes_dir(out_dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "probe-{}.json",
        crate::governance::fmt_compact_utc(p.taken_at_unix)
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("refusing to overwrite or cannot create {}", path.display()))?;
    f.write_all(&serde_json::to_vec_pretty(p)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

/// Latest probe file, if any.
pub fn load_latest_probe(out_dir: &Path) -> Result<Option<(PathBuf, ProbeFile)>> {
    let dir = probes_dir(out_dir);
    if !dir.exists() {
        return Ok(None);
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("probe-") && n.ends_with(".json"))
        })
        .collect();
    paths.sort();
    let Some(path) = paths.pop() else {
        return Ok(None);
    };
    let p: ProbeFile = serde_json::from_slice(&fs::read(&path)?)
        .with_context(|| format!("cannot parse {}", path.display()))?;
    if p.schema_version != PROBE_SCHEMA_VERSION {
        bail!(
            "{}: unsupported probe schema {}",
            path.display(),
            p.schema_version
        );
    }
    Ok(Some((path, p)))
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlClass {
    ConfirmedController,
    ConfirmedHotkey,
    OtherController,
    Unknown,
}

impl ControlClass {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ConfirmedController => "confirmed_controller",
            Self::ConfirmedHotkey => "confirmed_hotkey",
            Self::OtherController => "other_controller",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartDissolving {
    /// Verified controller and the neuron is locked: Governance would accept the request.
    Eligible,
    AlreadyDissolving,
    AlreadyDissolved,
    Spawning,
    /// We are not a verified controller; hotkeys cannot configure dissolve state.
    NoAuthority,
    /// Controller verified but dissolve state could not be determined.
    StateUnknown,
}

impl StartDissolving {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::AlreadyDissolving => "not_needed_already_dissolving",
            Self::AlreadyDissolved => "not_needed_already_dissolved",
            Self::Spawning => "not_possible_spawning",
            Self::NoAuthority => "no_authority",
            Self::StateUnknown => "state_unknown",
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct KnownPrincipal {
    pub label: String,
    pub principal: String,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ControlEntry {
    pub neuron_id: String,
    pub baseline_status: Status,
    /// What the probe (if any) returned: full / refused / call_failed / not_probed / none.
    pub probe: String,
    pub stake_e8s: Option<u64>,
    pub net_stake_e8s: Option<u64>,
    pub neuron_fees_e8s: Option<u64>,
    pub maturity_e8s: Option<u64>,
    pub staked_maturity_e8s: Option<u64>,
    pub controller: Option<String>,
    pub controller_label: Option<String>,
    pub hot_keys: Vec<String>,
    pub dissolve_state: &'static str,
    pub dissolve_delay_seconds: Option<u64>,
    pub unlock_unix: Option<u64>,
    pub access_class: ControlClass,
    pub reason: String,
    pub start_dissolving: StartDissolving,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Bucket {
    pub neurons: usize,
    pub net_stake_e8s: u128,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ControlReport {
    pub as_of_unix: u64,
    pub baseline_snapshot_unix: u64,
    pub probe_unix: Option<u64>,
    pub oracle_principal: String,
    pub known_principals: Vec<KnownPrincipal>,
    pub total_neurons: usize,
    pub by_class: Vec<(ControlClass, Bucket)>,
    pub baseline_full: Bucket,
    pub baseline_info_only: Bucket,
    pub baseline_other: Bucket,
    /// Stake of confirmed controllers by dissolve state (net of fees).
    pub confirmed_controller_by_dissolve: Vec<(&'static str, Bucket)>,
    pub confirmed_controller_maturity_e8s: u128,
    pub confirmed_controller_staked_maturity_e8s: u128,
    pub eligible_for_start_dissolving: Vec<String>,
    pub entries: Vec<ControlEntry>,
}

fn label_of(p: &str, known: &[KnownPrincipal]) -> Option<String> {
    known
        .iter()
        .find(|k| k.principal == p)
        .map(|k| k.label.clone())
}

fn bucket_add(b: &mut Bucket, net: u64) {
    b.neurons += 1;
    b.net_stake_e8s += u128::from(net);
}

/// Pure classification from a (possibly absent) full record. Returns the class and a reason.
pub fn classify_control(
    full: Option<&NeuronRecord>,
    oracle: &str,
    known: &[KnownPrincipal],
    unknown_reason: String,
) -> (ControlClass, String) {
    let Some(r) = full else {
        return (ControlClass::Unknown, unknown_reason);
    };
    let ctrl = r.controller.as_deref();
    if ctrl == Some(oracle) {
        return (
            ControlClass::ConfirmedController,
            "full record shows the Oracle principal as controller".into(),
        );
    }
    if r.hot_keys.iter().any(|h| h == oracle) {
        let other = match ctrl {
            Some(c) => format!(
                "controller is {c}{}",
                label_of(c, known)
                    .map(|l| format!(" ({l})"))
                    .unwrap_or_default()
            ),
            None => "no controller reported".into(),
        };
        return (
            ControlClass::ConfirmedHotkey,
            format!("Oracle principal is a hotkey only (can vote/follow, cannot dissolve or disburse); {other}"),
        );
    }
    match ctrl {
        Some(c) => (
            ControlClass::OtherController,
            format!(
                "full record visible but controller is {c}{}; Oracle is neither controller nor hotkey",
                label_of(c, known).map(|l| format!(" ({l})")).unwrap_or_default()
            ),
        ),
        None => (
            ControlClass::Unknown,
            "full record visible but Governance reported no controller".into(),
        ),
    }
}

pub fn start_dissolving(class: ControlClass, d: DissolveClass) -> StartDissolving {
    if class != ControlClass::ConfirmedController {
        return StartDissolving::NoAuthority;
    }
    match d {
        DissolveClass::Locked => StartDissolving::Eligible,
        DissolveClass::Dissolving => StartDissolving::AlreadyDissolving,
        DissolveClass::Dissolved => StartDissolving::AlreadyDissolved,
        DissolveClass::Spawning => StartDissolving::Spawning,
        DissolveClass::Unknown => StartDissolving::StateUnknown,
    }
}

fn probe_reason(r: &NeuronRecord, probe: Option<&ProbeOutcome>) -> (String, &'static str) {
    if r.status == Status::NotFound {
        return (
            "Governance returned neither a full record nor public info for this ID".into(),
            "none",
        );
    }
    match probe {
        None => (
            "list_neurons returned public NeuronInfo only and get_full_neuron has not been attempted; \
             controller and hotkeys are not disclosed"
                .into(),
            "none",
        ),
        Some(ProbeOutcome::Refused { error_type, message }) => (
            format!(
                "Governance refused get_full_neuron (error_type {error_type}: {message}). The caller is neither \
                 controller nor hotkey, and Governance does not disclose the controller of such neurons"
            ),
            "refused",
        ),
        Some(ProbeOutcome::CallFailed { message }) => {
            (format!("get_full_neuron call failed ({message}); no evidence either way"), "call_failed")
        }
        Some(ProbeOutcome::NotProbed) => ("get_full_neuron was not attempted (budget or earlier failure)".into(), "not_probed"),
        Some(ProbeOutcome::Full { .. }) => (String::new(), "full"),
    }
}

pub fn build(
    baseline: &Snapshot,
    probe: Option<&ProbeFile>,
    known: Vec<KnownPrincipal>,
) -> ControlReport {
    let oracle = baseline.oracle_principal.as_str();
    let as_of = baseline
        .taken_at_unix
        .max(probe.map_or(0, |p| p.taken_at_unix));
    let mut entries = vec![];
    let (mut full_b, mut info_b, mut other_b) =
        (Bucket::default(), Bucket::default(), Bucket::default());

    for r in &baseline.neurons {
        let outcome = probe
            .and_then(|p| p.results.iter().find(|x| x.neuron_id == r.neuron_id))
            .map(|x| &x.outcome);
        // A probe result only upgrades neurons the baseline could not read.
        let effective: &NeuronRecord = match (r.status, outcome) {
            (Status::Full, _) => r,
            (_, Some(ProbeOutcome::Full { record })) => record,
            _ => r,
        };
        let have_full = effective.status == Status::Full;
        let (unknown_reason, probe_name) = probe_reason(
            r,
            if r.status == Status::Full {
                None
            } else {
                outcome
            },
        );
        let probe_name = if r.status == Status::Full {
            "not_needed"
        } else {
            probe_name
        };
        let (class, reason) = classify_control(
            have_full.then_some(effective),
            oracle,
            &known,
            unknown_reason,
        );
        let as_of_for_class = if r.status != Status::Full && have_full {
            as_of
        } else {
            baseline.taken_at_unix
        };
        let d = dissolve_class(effective, as_of_for_class);
        let stake = effective.cached_stake_e8s.or(effective.info_stake_e8s);
        let fees = effective.neuron_fees_e8s;
        let net = match (effective.cached_stake_e8s, fees) {
            (Some(s), Some(f)) => Some(s.saturating_sub(f)),
            _ => effective.info_stake_e8s,
        };
        match r.status {
            Status::Full => bucket_add(&mut full_b, net.unwrap_or(0)),
            Status::InfoOnly => bucket_add(&mut info_b, net.unwrap_or(0)),
            _ => bucket_add(&mut other_b, net.unwrap_or(0)),
        }
        let unlock_unix = match &effective.dissolve {
            Some(crate::snapshot::DissolveRec::WhenDissolvedTimestampSeconds(t)) => Some(*t),
            _ => None,
        };
        let delay = match &effective.dissolve {
            Some(crate::snapshot::DissolveRec::DelaySeconds(s)) => Some(*s),
            _ => effective.info_dissolve_delay_seconds,
        };
        entries.push(ControlEntry {
            neuron_id: r.neuron_id.clone(),
            baseline_status: r.status,
            probe: probe_name.into(),
            stake_e8s: stake,
            net_stake_e8s: net,
            neuron_fees_e8s: fees,
            maturity_e8s: effective.maturity_e8s,
            staked_maturity_e8s: effective.staked_maturity_e8s,
            controller_label: effective
                .controller
                .as_deref()
                .and_then(|c| label_of(c, &known)),
            controller: effective.controller.clone(),
            hot_keys: effective.hot_keys.clone(),
            dissolve_state: d.name(),
            dissolve_delay_seconds: delay,
            unlock_unix,
            access_class: class,
            reason,
            start_dissolving: start_dissolving(class, d),
        });
    }
    entries.sort_by(|a, b| {
        (a.access_class as u8, a.neuron_id.len(), &a.neuron_id).cmp(&(
            b.access_class as u8,
            b.neuron_id.len(),
            &b.neuron_id,
        ))
    });

    let classes = [
        ControlClass::ConfirmedController,
        ControlClass::ConfirmedHotkey,
        ControlClass::OtherController,
        ControlClass::Unknown,
    ];
    let by_class = classes
        .iter()
        .map(|c| {
            let mut b = Bucket::default();
            for e in entries.iter().filter(|e| e.access_class == *c) {
                bucket_add(&mut b, e.net_stake_e8s.unwrap_or(0));
            }
            (*c, b)
        })
        .collect();

    let mut by_diss: Vec<(&'static str, Bucket)> = vec![];
    let (mut mat, mut smat) = (0u128, 0u128);
    for e in entries
        .iter()
        .filter(|e| e.access_class == ControlClass::ConfirmedController)
    {
        match by_diss.iter_mut().find(|(n, _)| *n == e.dissolve_state) {
            Some((_, b)) => bucket_add(b, e.net_stake_e8s.unwrap_or(0)),
            None => {
                let mut b = Bucket::default();
                bucket_add(&mut b, e.net_stake_e8s.unwrap_or(0));
                by_diss.push((e.dissolve_state, b));
            }
        }
        mat += u128::from(e.maturity_e8s.unwrap_or(0));
        smat += u128::from(e.staked_maturity_e8s.unwrap_or(0));
    }
    let eligible = entries
        .iter()
        .filter(|e| e.start_dissolving == StartDissolving::Eligible)
        .map(|e| e.neuron_id.clone())
        .collect();

    ControlReport {
        as_of_unix: as_of,
        baseline_snapshot_unix: baseline.taken_at_unix,
        probe_unix: probe.map(|p| p.taken_at_unix),
        oracle_principal: baseline.oracle_principal.clone(),
        known_principals: known,
        total_neurons: entries.len(),
        by_class,
        baseline_full: full_b,
        baseline_info_only: info_b,
        baseline_other: other_b,
        confirmed_controller_by_dissolve: by_diss,
        confirmed_controller_maturity_e8s: mat,
        confirmed_controller_staked_maturity_e8s: smat,
        eligible_for_start_dissolving: eligible,
        entries,
    }
}

fn icp(e: u128) -> String {
    fmt_e8s(e)
}

fn opt_icp(v: Option<u64>) -> String {
    v.map_or("n/a".into(), |x| fmt_e8s(x.into()))
}

pub fn markdown(r: &ControlReport, reproduce: &str) -> String {
    let mut s = String::new();
    s.push_str("# stICP neuron control report\n\n");
    s.push_str(&format!(
        "Generated for data as of {}. Baseline snapshot: {}. Probe: {}.\n\n",
        fmt_utc(r.as_of_unix),
        fmt_utc(r.baseline_snapshot_unix),
        r.probe_unix.map_or(
            "none (offline classification from the baseline only)".into(),
            fmt_utc
        )
    ));
    s.push_str("READ-ONLY. Nothing in this report was executed against Governance except `list_neurons` and `get_full_neuron` queries.\n\n");
    s.push_str(&format!("Oracle principal: `{}`\n\n", r.oracle_principal));

    s.push_str("## What `full` and `info_only` prove\n\n");
    s.push_str("- `full`: Governance returned the complete neuron record to the Oracle principal. It lists the controller and hotkeys, so control can be established from the record itself.\n");
    s.push_str("- `info_only`: Governance returned only the public `NeuronInfo` (stake, state, dissolve delay, age, voting power). It proves the neuron **exists** and its public numbers. It proves **nothing** about who controls it: the Oracle is simply not authorized to see the full record (not controller, not hotkey), and Governance does not expose the controller of such neurons through any public API.\n");
    s.push_str(
        "- Ownership is never inferred from public information. Those neurons are `unknown`.\n\n",
    );

    s.push_str("## Reconciliation\n\n");
    s.push_str("| Baseline status | Neurons | Net stake (ICP) |\n|---|---:|---:|\n");
    for (n, b) in [
        ("full", &r.baseline_full),
        ("info_only", &r.baseline_info_only),
        ("other (not found / failed)", &r.baseline_other),
    ] {
        s.push_str(&format!(
            "| {n} | {} | {} |\n",
            b.neurons,
            icp(b.net_stake_e8s)
        ));
    }
    s.push_str(&format!(
        "| **total** | {} | {} |\n\n",
        r.total_neurons,
        icp(r.baseline_full.net_stake_e8s
            + r.baseline_info_only.net_stake_e8s
            + r.baseline_other.net_stake_e8s)
    ));
    s.push_str("| Access class | Neurons | Net stake (ICP) |\n|---|---:|---:|\n");
    for (c, b) in &r.by_class {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            c.name(),
            b.neurons,
            icp(b.net_stake_e8s)
        ));
    }
    s.push('\n');

    s.push_str("## Confirmed recoverable under current credentials\n\n");
    let cc = r
        .by_class
        .iter()
        .find(|(c, _)| *c == ControlClass::ConfirmedController)
        .map(|(_, b)| b.clone())
        .unwrap_or_default();
    s.push_str(&format!(
        "Verified controller (Oracle) of **{}** neurons holding **{} ICP** net stake (cached stake minus fees). This is *authority*, not liquidity: ICP leaves a neuron only after it is dissolved and disbursed.\n\n",
        cc.neurons, icp(cc.net_stake_e8s)
    ));
    s.push_str("| Dissolve state | Neurons | Net stake (ICP) |\n|---|---:|---:|\n");
    for (n, b) in &r.confirmed_controller_by_dissolve {
        s.push_str(&format!(
            "| {n} | {} | {} |\n",
            b.neurons,
            icp(b.net_stake_e8s)
        ));
    }
    s.push_str(&format!(
        "\nMaturity on these neurons: {} ICP-equivalent; staked maturity: {} ICP-equivalent (not included above; maturity is a current balance, not lifetime rewards).\n\n",
        icp(r.confirmed_controller_maturity_e8s), icp(r.confirmed_controller_staked_maturity_e8s)
    ));
    s.push_str(&format!(
        "`StartDissolving` would be accepted (not executed) for **{}** neurons: verified controller and currently locked. Hotkeys cannot start dissolving; neurons that are already dissolving or dissolved need no such call.\n\n",
        r.eligible_for_start_dissolving.len()
    ));

    s.push_str("## Limitation\n\n");
    s.push_str("For neurons the Oracle cannot read, Governance does not reveal the controller or hotkeys. Their controller could be another principal, a hotkey arrangement we are not part of, or the neuron may have been transferred/spawned elsewhere; this tool cannot tell which. To manage them, the controller principal's key is required (hotkeys cannot dissolve or disburse).\n\n");

    s.push_str("## Known principals\n\n");
    for k in &r.known_principals {
        s.push_str(&format!("- {}: `{}`\n", k.label, k.principal));
    }
    s.push_str("\n## Neurons\n\n");
    s.push_str("| Neuron | Class | Baseline | Probe | Net stake | Dissolve | StartDissolving | Controller | Hotkeys | Reason |\n|---|---|---|---|---:|---|---|---|---|---|\n");
    for e in &r.entries {
        let ctrl = match (&e.controller, &e.controller_label) {
            (Some(c), Some(l)) => format!("`{c}` ({l})"),
            (Some(c), None) => format!("`{c}`"),
            _ => "not disclosed".into(),
        };
        let status = match e.baseline_status {
            Status::Full => "full",
            Status::InfoOnly => "info_only",
            Status::NotFound => "not_found",
            Status::NotQueried => "not_queried",
            Status::QueryFailed => "query_failed",
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            e.neuron_id,
            e.access_class.name(),
            status,
            e.probe,
            opt_icp(e.net_stake_e8s),
            e.dissolve_state,
            e.start_dissolving.name(),
            ctrl,
            if e.hot_keys.is_empty() {
                "-".into()
            } else {
                e.hot_keys.join(", ")
            },
            e.reason.replace('|', "/"),
        ));
    }
    s.push_str("\n## Reproduce\n\n```\n");
    s.push_str(reproduce);
    s.push_str("\n```\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::tests::{full, snap};
    use crate::snapshot::DissolveRec;

    const ORACLE: &str = "xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe";
    const OTHER: &str = "pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe";

    fn known() -> Vec<KnownPrincipal> {
        vec![
            KnownPrincipal {
                label: "oracle".into(),
                principal: ORACLE.into(),
            },
            KnownPrincipal {
                label: "deposits".into(),
                principal: "hnwvc-lyaaa-aaaal-aaf6q-cai".into(),
            },
        ]
    }

    fn info(id: u64, stake: u64) -> NeuronRecord {
        let mut r = NeuronRecord::blank(id, Status::InfoOnly);
        r.info_stake_e8s = Some(stake);
        r.info_state = Some(1);
        r.info_dissolve_delay_seconds = Some(1000);
        r
    }

    #[test]
    fn controller_hotkey_other_unknown() {
        let c = full(1, 100, 0, 0, 0);
        assert_eq!(
            classify_control(Some(&c), ORACLE, &known(), String::new()).0,
            ControlClass::ConfirmedController
        );

        let mut h = full(2, 100, 0, 0, 0);
        h.controller = Some(OTHER.into());
        h.hot_keys = vec![ORACLE.into()];
        assert_eq!(
            classify_control(Some(&h), ORACLE, &known(), String::new()).0,
            ControlClass::ConfirmedHotkey
        );

        let mut o = full(3, 100, 0, 0, 0);
        o.controller = Some("hnwvc-lyaaa-aaaal-aaf6q-cai".into());
        let (cls, why) = classify_control(Some(&o), ORACLE, &known(), String::new());
        assert_eq!(cls, ControlClass::OtherController);
        assert!(why.contains("deposits"));

        let mut n = full(4, 100, 0, 0, 0);
        n.controller = None;
        assert_eq!(
            classify_control(Some(&n), ORACLE, &known(), String::new()).0,
            ControlClass::Unknown
        );
        assert_eq!(
            classify_control(None, ORACLE, &known(), "why".into()),
            (ControlClass::Unknown, "why".into())
        );
    }

    #[test]
    fn hotkey_never_gets_start_dissolving() {
        assert_eq!(
            start_dissolving(ControlClass::ConfirmedHotkey, DissolveClass::Locked),
            StartDissolving::NoAuthority
        );
        assert_eq!(
            start_dissolving(ControlClass::OtherController, DissolveClass::Locked),
            StartDissolving::NoAuthority
        );
        assert_eq!(
            start_dissolving(ControlClass::Unknown, DissolveClass::Locked),
            StartDissolving::NoAuthority
        );
        assert_eq!(
            start_dissolving(ControlClass::ConfirmedController, DissolveClass::Locked),
            StartDissolving::Eligible
        );
        assert_eq!(
            start_dissolving(ControlClass::ConfirmedController, DissolveClass::Dissolving),
            StartDissolving::AlreadyDissolving
        );
        assert_eq!(
            start_dissolving(ControlClass::ConfirmedController, DissolveClass::Dissolved),
            StartDissolving::AlreadyDissolved
        );
        assert_eq!(
            start_dissolving(ControlClass::ConfirmedController, DissolveClass::Spawning),
            StartDissolving::Spawning
        );
        assert_eq!(
            start_dissolving(ControlClass::ConfirmedController, DissolveClass::Unknown),
            StartDissolving::StateUnknown
        );
    }

    #[test]
    fn info_only_without_probe_is_unknown_and_never_inferred() {
        let s = snap(1_000_000, vec![full(1, 500, 50, 7, 3), info(2, 900)]);
        let r = build(&s, None, known());
        let e2 = r.entries.iter().find(|e| e.neuron_id == "2").unwrap();
        assert_eq!(e2.access_class, ControlClass::Unknown);
        assert_eq!(e2.start_dissolving, StartDissolving::NoAuthority);
        assert_eq!(e2.controller, None);
        assert!(e2.reason.contains("not been attempted"));
        let e1 = r.entries.iter().find(|e| e.neuron_id == "1").unwrap();
        assert_eq!(e1.access_class, ControlClass::ConfirmedController);
        assert_eq!(e1.net_stake_e8s, Some(450));
        assert_eq!(r.eligible_for_start_dissolving, vec!["1".to_string()]);
        assert_eq!(
            r.baseline_info_only,
            Bucket {
                neurons: 1,
                net_stake_e8s: 900
            }
        );
    }

    #[test]
    fn refused_probe_stays_unknown_with_explicit_reason() {
        let s = snap(1_000_000, vec![info(2, 900)]);
        let p = ProbeFile {
            schema_version: 1,
            taken_at_unix: 1_000_100,
            oracle_principal: ORACLE.into(),
            governance: "g".into(),
            method: "get_full_neuron".into(),
            signature_budget: 3,
            signatures_used: 1,
            results: vec![ProbeResult {
                neuron_id: "2".into(),
                outcome: ProbeOutcome::Refused {
                    error_type: 3,
                    message: "not authorized".into(),
                },
            }],
        };
        let r = build(&s, Some(&p), known());
        assert_eq!(r.entries[0].access_class, ControlClass::Unknown);
        assert_eq!(r.entries[0].probe, "refused");
        assert!(r.entries[0]
            .reason
            .contains("does not disclose the controller"));
    }

    #[test]
    fn probe_full_upgrades_info_only_neuron() {
        let s = snap(1_000_000, vec![info(2, 900)]);
        let mut rec = full(2, 1_000, 100, 5, 0);
        rec.controller = Some(OTHER.into());
        let mut h = full(2, 1_000, 100, 5, 0);
        h.controller = Some(OTHER.into());
        h.hot_keys = vec![ORACLE.into()];
        for (record, want, sd) in [
            (
                rec,
                ControlClass::OtherController,
                StartDissolving::NoAuthority,
            ),
            (
                h,
                ControlClass::ConfirmedHotkey,
                StartDissolving::NoAuthority,
            ),
            (
                full(2, 1_000, 100, 5, 0),
                ControlClass::ConfirmedController,
                StartDissolving::Eligible,
            ),
        ] {
            let p = ProbeFile {
                schema_version: 1,
                taken_at_unix: 1_000_100,
                oracle_principal: ORACLE.into(),
                governance: "g".into(),
                method: "get_full_neuron".into(),
                signature_budget: 3,
                signatures_used: 1,
                results: vec![ProbeResult {
                    neuron_id: "2".into(),
                    outcome: ProbeOutcome::Full {
                        record: Box::new(record),
                    },
                }],
            };
            let r = build(&s, Some(&p), known());
            assert_eq!(r.entries[0].access_class, want);
            assert_eq!(r.entries[0].start_dissolving, sd);
            assert_eq!(r.entries[0].net_stake_e8s, Some(900));
            assert_eq!(r.entries[0].baseline_status, Status::InfoOnly);
        }
    }

    #[test]
    fn dissolving_and_dissolved_controller_neurons_are_not_eligible() {
        let mut a = full(1, 100, 0, 0, 0);
        a.dissolve = Some(DissolveRec::WhenDissolvedTimestampSeconds(2_000_000));
        let mut b = full(2, 100, 0, 0, 0);
        b.dissolve = Some(DissolveRec::DelaySeconds(0));
        let s = snap(1_000_000, vec![a, b]);
        let r = build(&s, None, known());
        assert!(r.eligible_for_start_dissolving.is_empty());
        let by = |id: &str| {
            r.entries
                .iter()
                .find(|e| e.neuron_id == id)
                .unwrap()
                .start_dissolving
        };
        assert_eq!(by("1"), StartDissolving::AlreadyDissolving);
        assert_eq!(by("2"), StartDissolving::AlreadyDissolved);
    }

    #[test]
    fn totals_reconcile() {
        let s = snap(
            1_000_000,
            vec![full(1, 500, 0, 0, 0), info(2, 300), info(3, 200)],
        );
        let r = build(&s, None, known());
        let sum: u128 = r.by_class.iter().map(|(_, b)| b.net_stake_e8s).sum();
        assert_eq!(sum, 1_000);
        assert_eq!(r.total_neurons, 3);
        let md = markdown(&r, "cmd");
        assert!(md.contains("info_only") && md.contains("cmd"));
    }

    #[test]
    fn probe_file_roundtrips_as_json() {
        let p = ProbeFile {
            schema_version: 1,
            taken_at_unix: 5,
            oracle_principal: ORACLE.into(),
            governance: "g".into(),
            method: "get_full_neuron".into(),
            signature_budget: 3,
            signatures_used: 1,
            results: vec![
                ProbeResult {
                    neuron_id: "1".into(),
                    outcome: ProbeOutcome::Refused {
                        error_type: 3,
                        message: "m".into(),
                    },
                },
                ProbeResult {
                    neuron_id: "2".into(),
                    outcome: ProbeOutcome::NotProbed,
                },
                ProbeResult {
                    neuron_id: "3".into(),
                    outcome: ProbeOutcome::Full {
                        record: Box::new(full(3, 1, 0, 0, 0)),
                    },
                },
            ],
        };
        let back: ProbeFile = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }
}
