//! CSV and Markdown rendering. Pure functions over snapshots/history; no network, no signing.

use crate::governance::Access;
use crate::governance::{fmt_e8s, fmt_icp, fmt_utc};
use crate::history::{History, IntervalStatus, COMPOUNDING_PERIODS};
use crate::snapshot::{dissolve_class, DissolveClass, DissolveRec, NeuronRecord, Snapshot, Status};
use std::fmt::Write;

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref().map(|v| v.to_string()).unwrap_or_default()
}

fn unlock_utc(r: &NeuronRecord) -> String {
    match &r.dissolve {
        Some(DissolveRec::WhenDissolvedTimestampSeconds(t)) => fmt_utc(*t),
        _ => String::new(),
    }
}

fn status_name(s: Status) -> &'static str {
    match s {
        Status::Full => "full",
        Status::InfoOnly => "info_only",
        Status::NotFound => "not_found",
        Status::NotQueried => "not_queried",
        Status::QueryFailed => "query_failed",
    }
}

fn access_name(a: Access) -> &'static str {
    match a {
        Access::Controller => "controller",
        Access::HotKeyOnly => "hotkey_only",
        Access::ReadableWithoutAuthority => "readable_without_authority",
        Access::NotReadable => "not_readable",
    }
}

pub fn csv(s: &Snapshot) -> String {
    let mut out = String::from(
        "snapshot_utc,neuron_id,status,access,controller,hot_keys,cached_stake_e8s,cached_stake_icp,\
         neuron_fees_e8s,maturity_e8s,staked_maturity_e8s,auto_stake_maturity,dissolve_class,\
         dissolve_kind,dissolve_seconds,unlock_utc,info_state,info_stake_e8s,error\n",
    );
    let when = fmt_utc(s.taken_at_unix);
    for r in &s.neurons {
        let (kind, secs) = match &r.dissolve {
            Some(DissolveRec::DelaySeconds(v)) => ("delay_seconds", v.to_string()),
            Some(DissolveRec::WhenDissolvedTimestampSeconds(v)) => {
                ("when_dissolved_timestamp_seconds", v.to_string())
            }
            None => ("", String::new()),
        };
        let class = if r.is_full() || r.status == Status::InfoOnly {
            dissolve_class(r, s.taken_at_unix).name()
        } else {
            ""
        };
        let cols = [
            when.clone(),
            r.neuron_id.clone(),
            status_name(r.status).into(),
            access_name(r.access).into(),
            opt(&r.controller),
            r.hot_keys.join(";"),
            opt(&r.cached_stake_e8s),
            r.cached_stake_e8s.map(fmt_icp).unwrap_or_default(),
            opt(&r.neuron_fees_e8s),
            opt(&r.maturity_e8s),
            opt(&r.staked_maturity_e8s),
            opt(&r.auto_stake_maturity),
            class.into(),
            kind.into(),
            secs,
            unlock_utc(r),
            opt(&r.info_state),
            opt(&r.info_stake_e8s),
            opt(&r.error),
        ];
        out.push_str(
            &cols
                .iter()
                .map(|c| csv_field(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

pub fn fmt_ppm_pct(ppm: u128) -> String {
    format!("{}.{:04}%", ppm / 10_000, ppm % 10_000)
}

fn fmt_days(secs: u64) -> String {
    format!("{}.{:02} d", secs / 86_400, secs % 86_400 * 100 / 86_400)
}

#[derive(Default)]
struct Bucket {
    count: usize,
    stake: u128,
}

pub fn markdown(s: &Snapshot, h: &History) -> String {
    let mut o = String::new();
    let w = &mut o;
    let _ = writeln!(w, "# stICP NNS neuron audit\n");
    let _ = writeln!(
        w,
        "- Snapshot: **{}** (unix {})",
        fmt_utc(s.taken_at_unix),
        s.taken_at_unix
    );
    let _ = writeln!(w, "- Oracle principal: `{}`", s.oracle_principal);
    let _ = writeln!(
        w,
        "- Governance: `{}`, signing canister: `{}`",
        s.governance, s.signing_canister
    );
    let _ = writeln!(
        w,
        "- Inventory: {} IDs in `{}` ({} unique, {} duplicates), sha256 `{}`",
        s.inventory.original_count,
        s.inventory.source,
        s.inventory.unique_count,
        s.inventory
            .original_count
            .saturating_sub(s.inventory.unique_count),
        s.inventory.source_sha256
    );
    let q = &s.query;
    let _ = writeln!(
        w,
        "- Query: {}/{} batches of up to {}; signatures used {} of budget {}; **{}**\n",
        q.batches_completed,
        q.batches_planned,
        q.batch_size,
        q.signatures_used,
        q.signature_budget,
        if q.complete {
            "complete"
        } else {
            "INCOMPLETE - some neurons were not queried"
        }
    );

    let full: Vec<&NeuronRecord> = s.neurons.iter().filter(|r| r.is_full()).collect();
    let sum = |f: fn(&NeuronRecord) -> Option<u64>| {
        full.iter().map(|r| f(r).unwrap_or(0) as u128).sum::<u128>()
    };
    let _ = writeln!(w, "## Totals (fully readable neurons)\n");
    let _ = writeln!(w, "| Metric | Value |\n|---|---|");
    let _ = writeln!(
        w,
        "| Accessible neurons | {} of {} unique IDs |",
        full.len(),
        s.neurons.len()
    );
    let _ = writeln!(
        w,
        "| Total cached stake | {} ICP |",
        fmt_e8s(sum(|r| r.cached_stake_e8s))
    );
    let _ = writeln!(
        w,
        "| Total neuron fees | {} ICP |",
        fmt_e8s(sum(|r| r.neuron_fees_e8s))
    );
    let _ = writeln!(
        w,
        "| Total maturity (current balance) | {} ICP-equivalent |",
        fmt_e8s(sum(|r| r.maturity_e8s))
    );
    let _ = writeln!(
        w,
        "| Total staked maturity | {} ICP-equivalent |\n",
        fmt_e8s(sum(|r| r.staked_maturity_e8s))
    );

    let mut by_access: Vec<(&str, Bucket)> = vec![
        ("Controlled by Oracle", Bucket::default()),
        ("Hotkey only", Bucket::default()),
        ("Readable, no authority", Bucket::default()),
    ];
    for r in &full {
        let i = match r.access {
            Access::Controller => 0,
            Access::HotKeyOnly => 1,
            _ => 2,
        };
        by_access[i].1.count += 1;
        by_access[i].1.stake += r.cached_stake_e8s.unwrap_or(0) as u128;
    }
    let _ = writeln!(w, "## Authority\n");
    let _ = writeln!(w, "| Access | Neurons | Cached stake |\n|---|---|---|");
    for (n, b) in &by_access {
        let _ = writeln!(w, "| {n} | {} | {} ICP |", b.count, fmt_e8s(b.stake));
    }
    let _ = writeln!(
        w,
        "\nController authority means `manage_neuron` *would be permitted*; it is not tested here. \
         Hotkeys can vote/follow but cannot dissolve, split or disburse. Disbursing ICP additionally \
         requires a dissolved neuron and a working signing path.\n"
    );

    let classes = [
        DissolveClass::Dissolved,
        DissolveClass::Dissolving,
        DissolveClass::Locked,
        DissolveClass::Spawning,
        DissolveClass::Unknown,
    ];
    let _ = writeln!(w, "## Dissolve status (as of snapshot time)\n");
    let _ = writeln!(w, "| State | Neurons | Cached stake |\n|---|---|---|");
    for c in classes {
        let b = full
            .iter()
            .filter(|r| dissolve_class(r, s.taken_at_unix) == c)
            .fold(Bucket::default(), |mut b, r| {
                b.count += 1;
                b.stake += r.cached_stake_e8s.unwrap_or(0) as u128;
                b
            });
        let _ = writeln!(
            w,
            "| {} | {} | {} ICP |",
            c.name(),
            b.count,
            fmt_e8s(b.stake)
        );
    }
    let soonest = full
        .iter()
        .filter(|r| dissolve_class(r, s.taken_at_unix) == DissolveClass::Dissolving)
        .filter_map(|r| match r.dissolve {
            Some(DissolveRec::WhenDissolvedTimestampSeconds(t)) => Some(t),
            _ => None,
        })
        .min();
    if let Some(t) = soonest {
        let _ = writeln!(w, "\nNext unlock among dissolving neurons: {}", fmt_utc(t));
    }
    let _ = writeln!(
        w,
        "\nLocked neurons have no determinable unlock date until dissolving starts.\n"
    );

    let missing: Vec<&NeuronRecord> = s.neurons.iter().filter(|r| !r.is_full()).collect();
    let _ = writeln!(
        w,
        "## Historical IDs not found or not accessible ({})\n",
        missing.len()
    );
    if missing.is_empty() {
        let _ = writeln!(w, "None.\n");
    } else {
        let _ = writeln!(w, "| Neuron ID | Status | Public stake |\n|---|---|---|");
        for r in missing {
            let _ = writeln!(
                w,
                "| {} | {} | {} |",
                r.neuron_id,
                status_name(r.status),
                r.info_stake_e8s
                    .map(|v| format!("{} ICP", fmt_icp(v)))
                    .unwrap_or_else(|| "-".into())
            );
        }
        let _ = writeln!(w, "\n`not_found` means Governance returned nothing: the neuron does not exist or is not visible to the Oracle.\n");
    }

    history_section(w, h);

    let _ = writeln!(w, "## Interpretation limits\n");
    let _ = writeln!(w, "- Maturity is a **current balance**. It is not lifetime staking rewards: maturity is spawned, staked or disbursed over time, and a single snapshot says nothing about past or monthly rewards.");
    let _ = writeln!(w, "- Returns come only from snapshot-to-snapshot increases of maturity + staked maturity on neurons with no unexplained movement.");
    let _ = writeln!(w, "- Neurons without voting power (dissolving, or dissolve delay under 6 months) earn nothing and dilute the observed return if included in the base.");
    let _ = writeln!(
        w,
        "- Cached stake can lag the ledger until a refresh; this audit does not read the ledger."
    );
    o
}

fn history_section(w: &mut String, h: &History) {
    let _ = writeln!(w, "## Historical returns\n");
    let _ = writeln!(w, "Snapshots compared: {}\n", h.snapshot_count);
    for warn in &h.warnings {
        let _ = writeln!(w, "- WARNING: {warn}");
    }
    if let Some(msg) = &h.insufficient {
        let _ = writeln!(w, "**{msg}**\n");
    }
    if !h.intervals.is_empty() {
        let _ = writeln!(w, "| From | To | Length | Status | Comparable / excluded | Earned | Base | Observed APR |\n|---|---|---|---|---|---|---|---|");
        for i in &h.intervals {
            let status = match i.status {
                IntervalStatus::Valid => "valid",
                IntervalStatus::TooShort => "too short",
                IntervalStatus::NoComparableBase => "non-comparable",
            };
            let _ = writeln!(
                w,
                "| {} | {} | {} | {} | {} / {} | {} ICP | {} ICP | {} |",
                fmt_utc(i.from_unix),
                fmt_utc(i.to_unix),
                fmt_days(i.secs),
                status,
                i.comparable_count,
                i.excluded_count,
                fmt_e8s(i.earned_e8s),
                fmt_e8s(i.base_e8s),
                i.apr_ppm.map(fmt_ppm_pct).unwrap_or_else(|| "n/a".into())
            );
        }
        let _ = writeln!(w);
        let mut any = false;
        for i in &h.intervals {
            for n in i.neurons.iter().filter(|n| !n.events.is_empty()) {
                if !any {
                    let _ = writeln!(w, "### Movements between snapshots\n");
                    let _ = writeln!(w, "Neurons marked *excluded* are non-comparable for that interval: their maturity change is NOT counted as rewards.\n");
                    let _ = writeln!(w, "| Interval end | Neuron | Event | Detail | Effect |\n|---|---|---|---|---|");
                    any = true;
                }
                for e in &n.events {
                    let _ = writeln!(
                        w,
                        "| {} | {} | {} | {} | {} |",
                        fmt_utc(i.to_unix),
                        n.neuron_id,
                        e.kind.name(),
                        e.detail,
                        if e.kind.breaks_comparability() {
                            "excluded"
                        } else {
                            "info"
                        }
                    );
                }
            }
        }
        if any {
            let _ = writeln!(w);
        }
    }
    let Some(a) = &h.aggregate else { return };
    let pct = |v: Option<u128>| {
        v.map(fmt_ppm_pct)
            .unwrap_or_else(|| "n/a (overflow)".into())
    };
    let _ = writeln!(
        w,
        "### Aggregate over {} valid interval(s), {}\n",
        a.valid_intervals,
        fmt_days(a.span_secs as u64)
    );
    let _ = writeln!(w, "| Figure | Value | Nature |\n|---|---|---|");
    let _ = writeln!(
        w,
        "| Rewards observed (comparable neurons) | {} ICP-equivalent | observed |",
        fmt_e8s(a.earned_e8s)
    );
    let _ = writeln!(
        w,
        "| Observed APR (simple, annualized) | {} | observed, time-weighted |",
        pct(a.observed_apr_ppm)
    );
    let _ = writeln!(
        w,
        "| Projected APY (compound) | {} | PROJECTION: assumes the observed APR compounds {COMPOUNDING_PERIODS} times a year; true only if maturity is restaked |",
        pct(a.projected_apy_ppm)
    );
    let _ = writeln!(w, "| Monthly reward estimate (observed pace) | {} ICP-equivalent | estimate: observed earnings scaled linearly to 30.4375 days |", fmt_e8s(a.monthly_observed_e8s));
    let _ = writeln!(
        w,
        "| Monthly reward estimate (current base) | {} ICP-equivalent | PROJECTION: APR/12 on {} ICP current base of all readable neurons |",
        a.projected_monthly_on_current_base_e8s.map(fmt_e8s).unwrap_or_else(|| "n/a".into()),
        fmt_e8s(a.current_base_e8s)
    );
    let r = &a.revenue;
    let _ = writeln!(
        w,
        "\n### Protocol revenue estimate (gross share {}.{:02}%)\n",
        r.share_bps / 100,
        r.share_bps % 100
    );
    let _ = writeln!(w, "| Figure | Value | Nature |\n|---|---|---|");
    let _ = writeln!(
        w,
        "| Gross share of observed rewards | {} ICP-equivalent | derived from observed rewards |",
        fmt_e8s(r.observed_gross_e8s)
    );
    let _ = writeln!(
        w,
        "| Projected monthly gross | {} ICP-equivalent | PROJECTION |",
        fmt_e8s(r.projected_monthly_gross_e8s)
    );
    let _ = writeln!(
        w,
        "| Projected annual gross | {} ICP-equivalent | PROJECTION |",
        fmt_e8s(r.projected_annual_gross_e8s)
    );
    let _ = writeln!(w, "| Actual realized fees | NOT MEASURED | requires the deposits-canister fee records; this tool does not read them |");
    let _ = writeln!(w, "\nThe share is a configured assumption applied to neuron rewards. It excludes affiliate/referral fees, so net protocol revenue is lower, and it says nothing about fees actually collected.\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::analyze;
    use crate::snapshot::tests::{full, snap};
    use crate::snapshot::NeuronRecord;

    #[test]
    fn csv_has_header_one_row_per_neuron_and_quotes_fields() {
        let mut r = full(5, 12_345, 1, 2, 3);
        r.hot_keys = vec!["a".into(), "b".into()];
        r.error = Some("bad, \"quoted\"".into());
        let s = snap(
            1_700_000_000,
            vec![r, NeuronRecord::blank(6, Status::NotFound)],
        );
        let out = csv(&s);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        let cols = lines[0].split(',').count();
        assert!(lines[1].contains(",5,full,controller,"));
        assert!(lines[1].contains(",a;b,12345,0.00012345,1,2,3,"));
        assert!(lines[1].ends_with("\"bad, \"\"quoted\"\"\""));
        assert!(lines[2].contains(",6,not_found,not_readable,"));
        assert_eq!(lines[2].split(',').count(), cols);
    }

    #[test]
    fn ppm_formatting() {
        assert_eq!(fmt_ppm_pct(36_525), "3.6525%");
        assert_eq!(fmt_ppm_pct(5), "0.0005%");
        assert_eq!(fmt_ppm_pct(1_000_000), "100.0000%");
    }

    #[test]
    fn single_snapshot_report_states_insufficient_history_and_no_returns() {
        let s = snap(
            1_700_000_000,
            vec![
                full(1, 5_000_000_000, 0, 1, 2),
                NeuronRecord::blank(2, Status::NotFound),
            ],
        );
        let md = markdown(&s, &analyze(&[&s], 86_400, 1000));
        assert!(md.contains("INSUFFICIENT HISTORY"));
        assert!(md.contains("| Accessible neurons | 1 of 2 unique IDs |"));
        assert!(md.contains("| Total cached stake | 50.00000000 ICP |"));
        assert!(md.contains("| 2 | not_found | - |"));
        assert!(!md.contains("Observed APR"));
        assert!(md.contains("not lifetime staking rewards"));
    }

    #[test]
    fn two_snapshot_report_labels_observed_projected_and_unmeasured() {
        let a = snap(1_700_000_000, vec![full(1, 100_000_000_000, 0, 0, 0)]);
        let b = snap(
            1_700_086_400,
            vec![full(1, 100_000_000_000, 0, 10_000_000, 0)],
        );
        let md = markdown(&b, &analyze(&[&a, &b], 86_400, 1000));
        assert!(md.contains("3.6525%"));
        assert!(md.contains("PROJECTION"));
        assert!(md.contains("NOT MEASURED"));
        assert!(md.contains("excludes affiliate"));
        assert!(md.contains("gross share 10.00%"));
    }
}
