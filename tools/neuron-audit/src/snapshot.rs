//! Immutable, timestamped JSON snapshots of the audited neurons.
//! All balances are raw e8s integers; neuron IDs are strings (they exceed 2^53, which most
//! JSON tooling cannot represent exactly).

use crate::governance::{classify, Access, DissolveState, Neuron, NeuronInfo};
use anyhow::{bail, Context, Result};
use candid::Principal;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Governance returned the full neuron (the Oracle is controller, hotkey or otherwise allowed).
    Full,
    /// Only public `neuron_info` came back: the neuron exists but its record is not readable.
    InfoOnly,
    /// Nothing came back: the neuron does not exist or is not visible to the Oracle.
    NotFound,
    /// The query for this neuron's batch was never attempted (earlier batch failed).
    NotQueried,
    /// The query for this neuron's batch failed.
    QueryFailed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", content = "seconds", rename_all = "snake_case")]
pub enum DissolveRec {
    DelaySeconds(u64),
    WhenDissolvedTimestampSeconds(u64),
}

impl From<&DissolveState> for DissolveRec {
    fn from(d: &DissolveState) -> Self {
        match d {
            DissolveState::DissolveDelaySeconds(s) => Self::DelaySeconds(*s),
            DissolveState::WhenDissolvedTimestampSeconds(s) => {
                Self::WhenDissolvedTimestampSeconds(*s)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NeuronRecord {
    pub neuron_id: String,
    pub status: Status,
    pub access: Access,
    pub controller: Option<String>,
    pub hot_keys: Vec<String>,
    pub cached_stake_e8s: Option<u64>,
    pub neuron_fees_e8s: Option<u64>,
    pub maturity_e8s: Option<u64>,
    /// Governance omits this field when zero; recorded as 0 for `full` records.
    pub staked_maturity_e8s: Option<u64>,
    pub auto_stake_maturity: Option<bool>,
    pub dissolve: Option<DissolveRec>,
    pub spawn_at_timestamp_seconds: Option<u64>,
    pub aging_since_timestamp_seconds: Option<u64>,
    pub created_timestamp_seconds: Option<u64>,
    /// Public `neuron_info` view (1 locked, 2 dissolving, 3 dissolved, 4 spawning).
    pub info_state: Option<i32>,
    pub info_stake_e8s: Option<u64>,
    pub info_dissolve_delay_seconds: Option<u64>,
    pub error: Option<String>,
}

impl NeuronRecord {
    pub fn blank(id: u64, status: Status) -> Self {
        Self {
            neuron_id: id.to_string(),
            status,
            access: Access::NotReadable,
            controller: None,
            hot_keys: vec![],
            cached_stake_e8s: None,
            neuron_fees_e8s: None,
            maturity_e8s: None,
            staked_maturity_e8s: None,
            auto_stake_maturity: None,
            dissolve: None,
            spawn_at_timestamp_seconds: None,
            aging_since_timestamp_seconds: None,
            created_timestamp_seconds: None,
            info_state: None,
            info_stake_e8s: None,
            info_dissolve_delay_seconds: None,
            error: None,
        }
    }

    pub fn from_response(
        id: u64,
        full: Option<&Neuron>,
        info: Option<&NeuronInfo>,
        oracle: &Principal,
    ) -> Self {
        let status = match (full, info) {
            (Some(_), _) => Status::Full,
            (None, Some(_)) => Status::InfoOnly,
            (None, None) => Status::NotFound,
        };
        let mut r = Self::blank(id, status);
        if let Some(i) = info {
            r.info_state = Some(i.state);
            r.info_stake_e8s = Some(i.stake_e8s);
            r.info_dissolve_delay_seconds = Some(i.dissolve_delay_seconds);
            r.created_timestamp_seconds = Some(i.created_timestamp_seconds);
        }
        if let Some(n) = full {
            r.access = classify(Some(n), oracle);
            r.controller = n.controller.map(|p| p.to_text());
            r.hot_keys = n.hot_keys.iter().map(|p| p.to_text()).collect();
            r.cached_stake_e8s = Some(n.cached_neuron_stake_e8s);
            r.neuron_fees_e8s = Some(n.neuron_fees_e8s);
            r.maturity_e8s = Some(n.maturity_e8s_equivalent);
            r.staked_maturity_e8s = Some(n.staked_maturity_e8s_equivalent.unwrap_or(0));
            r.auto_stake_maturity = n.auto_stake_maturity;
            r.dissolve = n.dissolve_state.as_ref().map(DissolveRec::from);
            r.spawn_at_timestamp_seconds = n.spawn_at_timestamp_seconds;
            r.aging_since_timestamp_seconds = Some(n.aging_since_timestamp_seconds);
            r.created_timestamp_seconds = Some(n.created_timestamp_seconds);
        }
        r
    }

    pub fn is_full(&self) -> bool {
        self.status == Status::Full
    }

    pub fn id(&self) -> Option<u64> {
        self.neuron_id.parse().ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DissolveClass {
    Dissolved,
    Dissolving,
    Locked,
    Spawning,
    Unknown,
}

impl DissolveClass {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Dissolved => "dissolved",
            Self::Dissolving => "dissolving",
            Self::Locked => "locked",
            Self::Spawning => "spawning",
            Self::Unknown => "unknown",
        }
    }
}

/// Dissolve class as of `at_unix` (the snapshot time).
pub fn dissolve_class(r: &NeuronRecord, at_unix: u64) -> DissolveClass {
    if r.spawn_at_timestamp_seconds.is_some() {
        return DissolveClass::Spawning;
    }
    match &r.dissolve {
        Some(DissolveRec::DelaySeconds(0)) => DissolveClass::Dissolved,
        Some(DissolveRec::DelaySeconds(_)) => DissolveClass::Locked,
        Some(DissolveRec::WhenDissolvedTimestampSeconds(t)) if *t <= at_unix => {
            DissolveClass::Dissolved
        }
        Some(DissolveRec::WhenDissolvedTimestampSeconds(_)) => DissolveClass::Dissolving,
        None => match r.info_state {
            Some(1) => DissolveClass::Locked,
            Some(2) => DissolveClass::Dissolving,
            Some(3) => DissolveClass::Dissolved,
            Some(4) => DissolveClass::Spawning,
            _ => DissolveClass::Unknown,
        },
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InventoryMeta {
    pub source: String,
    pub source_sha256: String,
    pub original_count: usize,
    pub unique_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct QueryMeta {
    pub batch_size: usize,
    pub batches_planned: usize,
    pub batches_completed: usize,
    pub signature_budget: u32,
    pub signatures_used: u32,
    /// True only if every planned batch succeeded.
    pub complete: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub schema_version: u32,
    pub tool_version: String,
    pub taken_at_unix: u64,
    pub governance: String,
    pub signing_canister: String,
    pub oracle_principal: String,
    pub inventory: InventoryMeta,
    pub query: QueryMeta,
    pub neurons: Vec<NeuronRecord>,
}

pub fn snapshots_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("snapshots")
}

/// Writes a new snapshot file. Never overwrites (`create_new`) and leaves the file read-only.
pub fn write_snapshot(out_dir: &Path, snap: &Snapshot) -> Result<PathBuf> {
    let dir = snapshots_dir(out_dir);
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let name = format!(
        "snapshot-{}.json",
        crate::governance::fmt_compact_utc(snap.taken_at_unix)
    );
    let path = dir.join(name);
    let json = serde_json::to_vec_pretty(snap)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("refusing to overwrite or cannot create {}", path.display()))?;
    f.write_all(&json)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

/// Loads every `snapshot-*.json` in chronological order.
pub fn load_snapshots(out_dir: &Path) -> Result<Vec<(PathBuf, Snapshot)>> {
    let dir = snapshots_dir(out_dir);
    let mut out = vec![];
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        let is_snapshot = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("snapshot-") && n.ends_with(".json"))
            .unwrap_or(false);
        if !is_snapshot {
            continue;
        }
        let snap: Snapshot = serde_json::from_slice(&fs::read(&path)?)
            .with_context(|| format!("cannot parse {}", path.display()))?;
        if snap.schema_version != SCHEMA_VERSION {
            bail!(
                "{}: unsupported schema_version {}",
                path.display(),
                snap.schema_version
            );
        }
        out.push((path, snap));
    }
    out.sort_by(|a, b| (a.1.taken_at_unix, &a.0).cmp(&(b.1.taken_at_unix, &b.0)));
    Ok(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn full(id: u64, stake: u64, fees: u64, maturity: u64, staked: u64) -> NeuronRecord {
        let mut r = NeuronRecord::blank(id, Status::Full);
        r.access = Access::Controller;
        r.controller =
            Some("xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe".into());
        r.cached_stake_e8s = Some(stake);
        r.neuron_fees_e8s = Some(fees);
        r.maturity_e8s = Some(maturity);
        r.staked_maturity_e8s = Some(staked);
        r.dissolve = Some(DissolveRec::DelaySeconds(86_400 * 365));
        r
    }

    pub fn snap(taken_at_unix: u64, neurons: Vec<NeuronRecord>) -> Snapshot {
        Snapshot {
            schema_version: SCHEMA_VERSION,
            tool_version: "test".into(),
            taken_at_unix,
            governance: "rrkah-fqaaa-aaaaa-aaaaq-cai".into(),
            signing_canister: "onfif-zaaaa-aaaar-qaama-cai".into(),
            oracle_principal: "xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe"
                .into(),
            inventory: InventoryMeta {
                source: "ids.txt".into(),
                source_sha256: "00".into(),
                original_count: neurons.len(),
                unique_count: neurons.len(),
            },
            query: QueryMeta {
                batch_size: 10,
                batches_planned: 1,
                batches_completed: 1,
                signature_budget: 4,
                signatures_used: 1,
                complete: true,
            },
            neurons,
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "neuron-audit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn json_keeps_raw_e8s_and_string_ids() {
        let s = snap(
            1_700_000_000,
            vec![full(16136654443876485299, 12_537_572_284, 7, 5, 9)],
        );
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"neuron_id\":\"16136654443876485299\""));
        assert!(json.contains("\"cached_stake_e8s\":12537572284"));
        assert!(json.contains("\"dissolve\":{\"kind\":\"delay_seconds\",\"seconds\":31536000}"));
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.neurons[0].id(), Some(16136654443876485299));
    }

    #[test]
    fn snapshots_are_write_once_read_only_and_sorted() {
        let dir = tmpdir("snap");
        let p2 = write_snapshot(&dir, &snap(1_700_086_400, vec![full(1, 1, 0, 0, 0)])).unwrap();
        let p1 = write_snapshot(&dir, &snap(1_700_000_000, vec![full(1, 1, 0, 0, 0)])).unwrap();
        assert!(fs::metadata(&p1).unwrap().permissions().readonly());
        assert!(p1
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("snapshot-2023"));
        // Same timestamp again must fail instead of overwriting.
        assert!(write_snapshot(&dir, &snap(1_700_000_000, vec![])).is_err());
        let loaded = load_snapshots(&dir).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].0, p1);
        assert_eq!(loaded[1].0, p2);
        assert_eq!(loaded[0].1.neurons.len(), 1);
        for (p, _) in &loaded {
            let mut perms = fs::metadata(p).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            fs::set_permissions(p, perms).unwrap();
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_unknown_schema() {
        let dir = tmpdir("schema");
        let mut s = snap(1_700_000_000, vec![]);
        s.schema_version = 99;
        fs::create_dir_all(snapshots_dir(&dir)).unwrap();
        fs::write(
            snapshots_dir(&dir).join("snapshot-x.json"),
            serde_json::to_vec(&s).unwrap(),
        )
        .unwrap();
        assert!(load_snapshots(&dir)
            .unwrap_err()
            .to_string()
            .contains("schema_version"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dissolve_classes() {
        let mut r = full(1, 1, 0, 0, 0);
        let now = 1_000_000;
        assert_eq!(dissolve_class(&r, now), DissolveClass::Locked);
        r.dissolve = Some(DissolveRec::DelaySeconds(0));
        assert_eq!(dissolve_class(&r, now), DissolveClass::Dissolved);
        r.dissolve = Some(DissolveRec::WhenDissolvedTimestampSeconds(now + 1));
        assert_eq!(dissolve_class(&r, now), DissolveClass::Dissolving);
        r.dissolve = Some(DissolveRec::WhenDissolvedTimestampSeconds(now));
        assert_eq!(dissolve_class(&r, now), DissolveClass::Dissolved);
        r.spawn_at_timestamp_seconds = Some(5);
        assert_eq!(dissolve_class(&r, now), DissolveClass::Spawning);
        let mut info_only = NeuronRecord::blank(2, Status::InfoOnly);
        assert_eq!(dissolve_class(&info_only, now), DissolveClass::Unknown);
        info_only.info_state = Some(2);
        assert_eq!(dissolve_class(&info_only, now), DissolveClass::Dissolving);
    }

    #[test]
    fn records_from_responses_cover_all_statuses() {
        use crate::governance::{NeuronId, NeuronInfo};
        let oracle =
            Principal::from_text("xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe")
                .unwrap();
        let info = NeuronInfo {
            dissolve_delay_seconds: 10,
            state: 1,
            stake_e8s: 99,
            created_timestamp_seconds: 3,
            age_seconds: 0,
            voting_power: 0,
            retrieved_at_timestamp_seconds: 0,
        };
        let n = Neuron {
            id: Some(NeuronId { id: 5 }),
            controller: Some(oracle),
            hot_keys: vec![],
            cached_neuron_stake_e8s: 100,
            neuron_fees_e8s: 1,
            maturity_e8s_equivalent: 2,
            staked_maturity_e8s_equivalent: None,
            auto_stake_maturity: Some(true),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(10)),
            aging_since_timestamp_seconds: 0,
            created_timestamp_seconds: 3,
            spawn_at_timestamp_seconds: None,
        };
        let f = NeuronRecord::from_response(5, Some(&n), Some(&info), &oracle);
        assert_eq!((f.status, f.access), (Status::Full, Access::Controller));
        assert_eq!(f.staked_maturity_e8s, Some(0));
        assert_eq!(f.auto_stake_maturity, Some(true));
        let i = NeuronRecord::from_response(6, None, Some(&info), &oracle);
        assert_eq!(
            (i.status, i.access, i.cached_stake_e8s, i.info_stake_e8s),
            (Status::InfoOnly, Access::NotReadable, None, Some(99))
        );
        let m = NeuronRecord::from_response(7, None, None, &oracle);
        assert_eq!(m.status, Status::NotFound);
    }
}
