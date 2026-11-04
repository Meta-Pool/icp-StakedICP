//! Canonical neuron inventory (`audit-in/neurons.txt`): strict extraction of neuron IDs from an
//! explicit set of trusted sources, deterministic merge and atomic write. Offline only.
//!
//! IDs are extracted ONLY from named fields/columns or the `NEURONS=( ... )` bash array.
//! The inventory is a list of candidates; it is never authorization evidence.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `NEURONS=( ... )` bash array (check-neurons.sh).
    BashArray,
    /// CSV with a `neuron_id` / `Neuron ID` column.
    Csv,
    /// Audit snapshot: `neurons[].neuron_id`.
    Snapshot,
    /// control-report.json: `entries[].neuron_id`.
    ControlReport,
    /// controller-trace.json: `neurons[].neuron_id`, `neurons[].parent_neuron`,
    /// `split_children_no_longer_in_inventory[].parent`.
    ControllerTrace,
    /// Recovery disburse record/intent: top-level `neuron_id`.
    Disburse,
}

impl Kind {
    pub fn parse(s: &str) -> Result<Kind> {
        Ok(match s {
            "bash-array" => Kind::BashArray,
            "csv" => Kind::Csv,
            "snapshot" => Kind::Snapshot,
            "control-report" => Kind::ControlReport,
            "controller-trace" => Kind::ControllerTrace,
            "disburse" => Kind::Disburse,
            _ => bail!(
                "unknown source kind '{s}' (bash-array|csv|snapshot|control-report|controller-trace|disburse)"
            ),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::BashArray => "bash-array",
            Kind::Csv => "csv",
            Kind::Snapshot => "snapshot",
            Kind::ControlReport => "control-report",
            Kind::ControllerTrace => "controller-trace",
            Kind::Disburse => "disburse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub label: String,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub locator: String,
    pub text: String,
    pub reason: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Extraction {
    /// (id, locator) for every valid record, in source order.
    pub records: Vec<(u64, String)>,
    pub invalid: Vec<Invalid>,
}

impl Extraction {
    fn push_id(&mut self, locator: String, raw: &str) {
        match parse_id(raw) {
            Ok(id) => self.records.push((id, locator)),
            Err(reason) => self.invalid.push(Invalid {
                locator,
                text: raw.to_string(),
                reason,
            }),
        }
    }
    fn bad(&mut self, locator: String, text: &str, reason: &str) {
        self.invalid.push(Invalid {
            locator,
            text: text.chars().take(80).collect(),
            reason: reason.into(),
        });
    }
}

fn parse_id(raw: &str) -> std::result::Result<u64, String> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err("not an unsigned decimal integer".into());
    }
    match t.parse::<u64>() {
        Ok(0) => Err("zero is not a valid neuron ID".into()),
        Ok(v) => Ok(v),
        Err(_) => Err("exceeds u64".into()),
    }
}

pub fn extract_bash_array(text: &str) -> Extraction {
    let mut ex = Extraction::default();
    let mut inside = false;
    let mut found = false;
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let code = line.split('#').next().unwrap_or("");
        let mut rest = code.trim();
        if !inside {
            let Some(after) = rest.strip_prefix("NEURONS=(") else {
                continue;
            };
            if after.trim_start().starts_with("$(") || after.contains('"') {
                // Derived/dedup assignment, not a literal list of IDs.
                continue;
            }
            inside = true;
            found = true;
            rest = after;
        }
        let (body, closed) = match rest.find(')') {
            Some(p) => (&rest[..p], true),
            None => (rest, false),
        };
        for tok in body.split_whitespace() {
            ex.push_id(format!("line {n}"), tok);
        }
        if closed {
            inside = false;
        }
    }
    if inside {
        ex.bad("EOF".into(), "NEURONS=(", "unterminated array");
    }
    if !found {
        ex.bad("-".into(), "", "no literal NEURONS=( ... ) array found");
    }
    ex
}

pub fn extract_csv(text: &str) -> Extraction {
    let mut ex = Extraction::default();
    let mut lines = text.lines().enumerate();
    let Some((_, header)) = lines.next() else {
        ex.bad("-".into(), "", "empty file");
        return ex;
    };
    let cols: Vec<String> = header
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase().replace(' ', "_"))
        .collect();
    let idx: Vec<usize> = cols
        .iter()
        .enumerate()
        .filter(|(_, c)| *c == "neuron_id")
        .map(|(i, _)| i)
        .collect();
    if idx.len() != 1 {
        ex.bad(
            "line 1".into(),
            header,
            "expected exactly one neuron_id column",
        );
        return ex;
    }
    for (i, line) in lines {
        if line.trim().is_empty() {
            continue;
        }
        match line.split(',').nth(idx[0]) {
            Some(v) => ex.push_id(format!("line {}, column neuron_id", i + 1), v),
            None => ex.bad(format!("line {}", i + 1), line, "missing neuron_id column"),
        }
    }
    ex
}

fn json_ids(ex: &mut Extraction, v: Option<&Value>, locator: String) {
    match v {
        Some(Value::String(s)) => ex.push_id(locator, s),
        Some(Value::Number(n)) => ex.push_id(locator, &n.to_string()),
        Some(other) => ex.bad(locator, &other.to_string(), "unexpected JSON type"),
        None => ex.bad(locator, "", "field missing"),
    }
}

fn json_array<'a>(ex: &mut Extraction, root: &'a Value, key: &str, required: bool) -> &'a [Value] {
    match root.get(key).and_then(Value::as_array) {
        Some(a) => a,
        None => {
            if required {
                ex.bad(key.into(), "", "expected array is missing");
            }
            &[]
        }
    }
}

pub fn extract_json(kind: Kind, text: &str) -> Extraction {
    let mut ex = Extraction::default();
    let root: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            ex.bad("-".into(), "", &format!("invalid JSON: {e}"));
            return ex;
        }
    };
    match kind {
        Kind::Snapshot | Kind::ControlReport => {
            let key = if kind == Kind::Snapshot {
                "neurons"
            } else {
                "entries"
            };
            for (i, n) in json_array(&mut ex, &root, key, true).iter().enumerate() {
                json_ids(&mut ex, n.get("neuron_id"), format!("{key}[{i}].neuron_id"));
            }
        }
        Kind::ControllerTrace => {
            for (i, n) in json_array(&mut ex, &root, "neurons", true)
                .iter()
                .enumerate()
            {
                json_ids(
                    &mut ex,
                    n.get("neuron_id"),
                    format!("neurons[{i}].neuron_id"),
                );
                if let Some(p) = n.get("parent_neuron").filter(|p| !p.is_null()) {
                    json_ids(&mut ex, Some(p), format!("neurons[{i}].parent_neuron"));
                }
            }
            for (i, n) in json_array(
                &mut ex,
                &root,
                "split_children_no_longer_in_inventory",
                false,
            )
            .iter()
            .enumerate()
            {
                json_ids(
                    &mut ex,
                    n.get("parent"),
                    format!("split_children_no_longer_in_inventory[{i}].parent"),
                );
            }
        }
        Kind::Disburse => json_ids(&mut ex, root.get("neuron_id"), "neuron_id".into()),
        _ => ex.bad("-".into(), "", "not a JSON kind"),
    }
    ex
}

pub fn extract(kind: Kind, text: &str) -> Extraction {
    match kind {
        Kind::BashArray => extract_bash_array(text),
        Kind::Csv => extract_csv(text),
        _ => extract_json(kind, text),
    }
}

/// Per-source result.
#[derive(Debug, Clone)]
pub struct SourceResult {
    pub source: Source,
    pub present: bool,
    pub ex: Extraction,
}

impl SourceResult {
    pub fn extracted(&self) -> usize {
        self.ex.records.len()
    }
    pub fn unique(&self) -> BTreeSet<u64> {
        self.ex.records.iter().map(|(i, _)| *i).collect()
    }
}

fn repo_dir(crate_dir: &Path) -> PathBuf {
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| crate_dir.join("../.."))
}

/// The sources `--include-history` trusts: fixed, repository-relative locations.
pub fn history_sources(crate_dir: &Path) -> Result<Vec<(PathBuf, Kind)>> {
    let repo = repo_dir(crate_dir);
    let mut out = vec![
        (
            repo.join("recovery/2026-10-22/check-neurons.sh"),
            Kind::BashArray,
        ),
        (
            repo.join("recovery/2026-10-22/neurons-audit.txt"),
            Kind::Csv,
        ),
        (crate_dir.join("audit-out/neurons-latest.csv"), Kind::Csv),
        (
            crate_dir.join("audit-out/control-report.json"),
            Kind::ControlReport,
        ),
        (
            crate_dir.join("audit-out/controller-trace.json"),
            Kind::ControllerTrace,
        ),
    ];
    for (dir, prefix, suffix, kind) in [
        ("audit-out/snapshots", "snapshot-", ".json", Kind::Snapshot),
        ("audit-out/recovery", "disburse-", ".json", Kind::Disburse),
    ] {
        let d = crate_dir.join(dir);
        if !d.is_dir() {
            continue;
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(&d)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
            })
            .collect();
        files.sort();
        out.extend(files.into_iter().map(|f| (f, kind)));
    }
    Ok(out)
}

pub fn read_source(path: &Path, kind: Kind, label: String) -> Result<SourceResult> {
    let source = Source { label, kind };
    if !path.exists() {
        return Ok(SourceResult {
            source,
            present: false,
            ex: Extraction::default(),
        });
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(SourceResult {
        ex: extract(kind, &text),
        source,
        present: true,
    })
}

/// Existing canonical file: strict. Any non-comment line that is not exactly one valid ID is an
/// error, so a hand-edited file is never silently rewritten.
pub fn read_canonical(path: &Path) -> Result<BTreeSet<u64>> {
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut set = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let id = parse_id(l).map_err(|e| {
            anyhow!(
                "{}:{}: invalid canonical entry '{l}': {e}",
                path.display(),
                i + 1
            )
        })?;
        set.insert(id);
    }
    Ok(set)
}

pub fn render_canonical(ids: &BTreeSet<u64>) -> String {
    let mut s = String::new();
    for id in ids {
        let _ = writeln!(s, "{id}");
    }
    s
}

/// Write via a temp file in the same directory + rename. Returns false when already identical.
pub fn atomic_write(path: &Path, content: &str) -> Result<bool> {
    if std::fs::read_to_string(path).is_ok_and(|c| c == content) {
        return Ok(false);
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(d) = dir {
        std::fs::create_dir_all(d)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("bad output path {}", path.display()))?
        .to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.tmp{}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(true)
}

pub struct Merged {
    pub ids: BTreeSet<u64>,
    /// id -> sorted "label (locator)" provenance entries.
    pub provenance: BTreeMap<u64, BTreeSet<String>>,
}

pub fn merge(canonical: &BTreeSet<u64>, results: &[SourceResult]) -> Merged {
    let mut ids = canonical.clone();
    let mut provenance: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for r in results {
        for (id, loc) in &r.ex.records {
            ids.insert(*id);
            provenance
                .entry(*id)
                .or_default()
                .insert(format!("{} ({loc})", r.source.label));
        }
    }
    Merged { ids, provenance }
}

/// Deterministic Markdown report (no timestamps; independent of the current canonical file,
/// except for the "canonical-only" line).
pub fn report(canonical: &BTreeSet<u64>, results: &[SourceResult], m: &Merged) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Neuron inventory report\n");
    let total: usize = results.iter().map(|r| r.extracted()).sum();
    let _ = writeln!(s, "- Sources configured: {}", results.len());
    let _ = writeln!(s, "- IDs extracted (all sources, with duplicates): {total}");
    let _ = writeln!(s, "- Unique IDs in canonical inventory: {}", m.ids.len());
    let from_sources: BTreeSet<u64> = m.provenance.keys().copied().collect();
    let canonical_only: Vec<_> = canonical.difference(&from_sources).collect();
    let _ = writeln!(
        s,
        "- Canonical IDs found in no configured source: {}",
        canonical_only.len()
    );
    for id in &canonical_only {
        let _ = writeln!(s, "  - {id}");
    }
    let _ = writeln!(s, "\n## Per source\n");
    let _ = writeln!(
        s,
        "| Source | Kind | Present | Extracted | Unique | Duplicates | Only here | Invalid |\n|---|---|---|---|---|---|---|---|"
    );
    for r in results {
        let uniq = r.unique();
        let only = uniq
            .iter()
            .filter(|id| {
                results
                    .iter()
                    .filter(|o| o.source.label != r.source.label)
                    .all(|o| !o.unique().contains(id))
            })
            .count();
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            r.source.label,
            r.source.kind.name(),
            if r.present { "yes" } else { "no" },
            r.extracted(),
            uniq.len(),
            r.extracted() - uniq.len(),
            only,
            r.ex.invalid.len()
        );
    }
    let _ = writeln!(s, "\n## IDs found in exactly one source\n");
    for r in results {
        let ids: Vec<String> = r
            .unique()
            .into_iter()
            .filter(|id| {
                results
                    .iter()
                    .filter(|o| o.source.label != r.source.label)
                    .all(|o| !o.unique().contains(id))
            })
            .map(|i| i.to_string())
            .collect();
        if !ids.is_empty() {
            let _ = writeln!(s, "- {}: {}", r.source.label, ids.join(", "));
        }
    }
    let _ = writeln!(s, "\n## Invalid or ambiguous records\n");
    let mut any = false;
    for r in results {
        for inv in &r.ex.invalid {
            any = true;
            let _ = writeln!(
                s,
                "- {} [{}]: `{}` - {}",
                r.source.label, inv.locator, inv.text, inv.reason
            );
        }
    }
    if !any {
        let _ = writeln!(s, "None.");
    }
    let _ = writeln!(s, "\n## Provenance\n");
    for (id, p) in &m.provenance {
        let _ = writeln!(
            s,
            "- {id}: {}",
            p.iter().cloned().collect::<Vec<_>>().join("; ")
        );
    }
    s
}

/// Resolve a user-supplied path: absolute or cwd-relative as given.
pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn default_ids_file() -> PathBuf {
    crate_dir().join("audit-in/neurons.txt")
}

pub fn label_for(path: &Path, crate_dir: &Path) -> String {
    let repo = repo_dir(crate_dir);
    for base in [crate_dir.to_path_buf(), repo.clone()] {
        if let Ok(r) = path.strip_prefix(&base) {
            let r = r.to_string_lossy().to_string();
            return if base == repo {
                r
            } else {
                format!("tools/neuron-audit/{r}")
            };
        }
    }
    let norm = |p: &Path| std::fs::canonicalize(p).ok();
    if let (Some(p), Some(rp)) = (norm(path), norm(&repo)) {
        if let Ok(r) = p.strip_prefix(rp) {
            return r.to_string_lossy().to_string();
        }
    }
    path.to_string_lossy().to_string()
}

pub struct SyncArgs {
    pub out: PathBuf,
    pub report: Option<PathBuf>,
    pub include_history: bool,
    pub sources: Vec<(PathBuf, Kind)>,
    pub crate_dir: PathBuf,
    pub dry_run: bool,
}

/// Returns the number of unique IDs in the resulting inventory.
pub fn sync(a: &SyncArgs) -> Result<usize> {
    let canonical = read_canonical(&a.out)?;
    let mut specs: Vec<(PathBuf, Kind)> = Vec::new();
    if a.include_history {
        specs.extend(history_sources(&a.crate_dir)?);
    }
    specs.extend(a.sources.iter().cloned());
    let mut results = Vec::new();
    let mut seen = BTreeSet::new();
    for (p, k) in specs {
        let label = label_for(&p, &a.crate_dir);
        if !seen.insert(label.clone()) {
            continue;
        }
        results.push(read_source(&p, k, label)?);
    }
    results.sort_by(|x, y| x.source.label.cmp(&y.source.label));
    let merged = merge(&canonical, &results);

    println!("Canonical file   : {}", a.out.display());
    println!("Existing IDs     : {}", canonical.len());
    for r in &results {
        let new = r.unique().difference(&canonical).count();
        println!(
            "  {:<60} {} extracted={} unique={} new={} invalid={}",
            r.source.label,
            if r.present { "  " } else { "MISSING" },
            r.extracted(),
            r.unique().len(),
            new,
            r.ex.invalid.len()
        );
    }
    println!("Unique IDs after : {}", merged.ids.len());
    let invalid: usize = results.iter().map(|r| r.ex.invalid.len()).sum();
    if invalid > 0 {
        println!(
            "WARNING: {invalid} invalid/ambiguous record(s) were NOT imported; see the report."
        );
    }
    if a.dry_run {
        println!("Dry run: nothing written.");
        return Ok(merged.ids.len());
    }
    let changed = atomic_write(&a.out, &render_canonical(&merged.ids))?;
    println!(
        "{}",
        if changed {
            "Inventory written."
        } else {
            "Inventory unchanged."
        }
    );
    if let Some(rp) = &a.report {
        atomic_write(rp, &report(&canonical, &results, &merged))?;
        println!("Report           : {}", rp.display());
    }
    Ok(merged.ids.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("na-sync-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const SH: &str = r#"#!/usr/bin/env bash
GOVERNANCE="rrkah-fqaaa-aaaaa-aaaaq-cai"
total=18446744073709551615
NEURONS=(
18446744073709551615
5 7
5
)
NEURONS=($(printf '%s\n' "${NEURONS[@]}" | sort -u))
for id in "${NEURONS[@]}"; do echo 99999; done
"#;

    #[test]
    fn bash_array_only() {
        let ex = extract_bash_array(SH);
        let ids: Vec<u64> = ex.records.iter().map(|r| r.0).collect();
        assert_eq!(ids, vec![u64::MAX, 5, 7, 5]);
        assert!(ex.invalid.is_empty());
    }

    #[test]
    fn bash_array_malformed_reported() {
        let ex = extract_bash_array("NEURONS=(\n12\n0x10\n18446744073709551616\n0\n)\n");
        assert_eq!(ex.records.len(), 1);
        assert_eq!(ex.invalid.len(), 3);
        let ex = extract_bash_array("echo hi\n");
        assert_eq!(ex.invalid.len(), 1);
        let ex = extract_bash_array("NEURONS=(\n1\n");
        assert_eq!(ex.invalid.len(), 1);
    }

    #[test]
    fn csv_and_json_fields() {
        let ex = extract_csv("Neuron ID,Stake (ICP)\n18446744073709551615,12345678901\nabc,1\n");
        assert_eq!(ex.records.len(), 1);
        assert_eq!(ex.invalid.len(), 1);
        let ex = extract_json(
            Kind::Snapshot,
            r#"{"taken_at_unix":1793045253,"neurons":[{"neuron_id":"9","cached_stake_e8s":51197356573},{"neuron_id":null}]}"#,
        );
        assert_eq!(ex.records, vec![(9, "neurons[0].neuron_id".to_string())]);
        assert_eq!(ex.invalid.len(), 1);
        let ex = extract_json(
            Kind::ControllerTrace,
            r#"{"neurons":[{"neuron_id":"3","parent_neuron":"2"},{"neuron_id":"4","parent_neuron":null}],
                "split_children_no_longer_in_inventory":[{"parent":2863272345781569901,"balance_now_e8s":123456789012}]}"#,
        );
        let ids: Vec<u64> = ex.records.iter().map(|r| r.0).collect();
        assert_eq!(ids, vec![3, 2, 4, 2863272345781569901]);
        assert_eq!(extract_json(Kind::Disburse, "{").invalid.len(), 1);
    }

    #[test]
    fn merge_sorted_numeric_dedup_and_history_only() {
        let a = SourceResult {
            source: Source {
                label: "a".into(),
                kind: Kind::Csv,
            },
            present: true,
            ex: extract_csv("neuron_id\n100\n9\n9\n"),
        };
        let b = SourceResult {
            source: Source {
                label: "b".into(),
                kind: Kind::Snapshot,
            },
            present: true,
            ex: extract_json(
                Kind::Snapshot,
                r#"{"neurons":[{"neuron_id":"18446744073709551615"},{"neuron_id":"9"}]}"#,
            ),
        };
        let m = merge(&BTreeSet::new(), &[a.clone(), b.clone()]);
        assert_eq!(render_canonical(&m.ids), "9\n100\n18446744073709551615\n");
        assert_eq!(m.provenance[&9].len(), 3);
        assert_eq!(a.extracted() - a.unique().len(), 1);
        let rep = report(&BTreeSet::new(), &[a, b], &m);
        assert!(rep.contains("18446744073709551615"));
        assert!(rep.contains("b: 18446744073709551615"));
    }

    #[test]
    fn sync_is_idempotent_and_non_destructive() {
        let d = tmpdir("idem");
        let src = d.join("a.csv");
        std::fs::write(&src, "neuron_id\n30\n20\n").unwrap();
        let out = d.join("audit-in/neurons.txt");
        let args = |s: &Path| SyncArgs {
            out: out.clone(),
            report: Some(d.join("report.md")),
            include_history: false,
            sources: vec![(s.to_path_buf(), Kind::Csv)],
            crate_dir: d.clone(),
            dry_run: false,
        };
        assert_eq!(sync(&args(&src)).unwrap(), 2);
        let first = std::fs::read_to_string(&out).unwrap();
        assert_eq!(first, "20\n30\n");
        sync(&args(&src)).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), first);
        // A different source later keeps earlier IDs.
        let src2 = d.join("b.csv");
        std::fs::write(&src2, "neuron_id\n10\n").unwrap();
        sync(&args(&src2)).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "10\n20\n30\n");
        // Missing source never removes entries.
        sync(&args(&d.join("gone.csv"))).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "10\n20\n30\n");
        // Malformed canonical file is refused, untouched.
        std::fs::write(&out, "10\nbogus\n").unwrap();
        assert!(sync(&args(&src)).is_err());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "10\nbogus\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn default_path_is_independent_of_cwd() {
        let p = default_ids_file();
        assert!(p.is_absolute());
        assert!(
            p.ends_with("tools/neuron-audit/audit-in/neurons.txt")
                || p.ends_with("audit-in/neurons.txt")
        );
        let before = std::env::current_dir().unwrap();
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        let after = default_ids_file();
        std::env::set_current_dir(before).unwrap();
        assert_eq!(p, after);
    }
}
