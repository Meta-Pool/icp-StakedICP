//! Snapshot-to-snapshot comparison, observed returns and protocol revenue estimates.
//!
//! All arithmetic is integer (e8s as u128; rates in parts-per-million). Nothing here is
//! a lifetime reward figure: rewards are only the *increase* of maturity + staked maturity
//! between two snapshots, and only for neurons whose interval has no unexplained movement.

use crate::snapshot::{dissolve_class, NeuronRecord, Snapshot, Status};
use std::collections::{BTreeMap, BTreeSet};

/// Julian year, 365.25 days.
pub const YEAR_SECS: u128 = 31_557_600;
pub const MONTH_SECS: u128 = YEAR_SECS / 12;
pub const PPM: u128 = 1_000_000;
const SCALE: u128 = 1_000_000_000_000;
/// Compounding periods assumed by the projected APY.
pub const COMPOUNDING_PERIODS: u32 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    NewNeuron,
    MissingNeuron,
    StakeIncrease,
    StakeDecrease,
    PossibleDisbursement,
    FeesChanged,
    MaturityOutflow,
    UnexplainedMovement,
    Unobservable,
    // Informational: do not affect comparability.
    MaturityStaked,
    DissolveChanged,
    ControlChanged,
    AutoStakeChanged,
}

impl EventKind {
    /// Events after which the neuron's maturity delta can no longer be read as pure rewards.
    pub fn breaks_comparability(&self) -> bool {
        !matches!(
            self,
            Self::MaturityStaked
                | Self::DissolveChanged
                | Self::ControlChanged
                | Self::AutoStakeChanged
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::NewNeuron => "new_neuron",
            Self::MissingNeuron => "missing_neuron",
            Self::StakeIncrease => "stake_increase",
            Self::StakeDecrease => "stake_decrease",
            Self::PossibleDisbursement => "possible_disbursement",
            Self::FeesChanged => "fees_changed",
            Self::MaturityOutflow => "maturity_outflow",
            Self::UnexplainedMovement => "unexplained_movement",
            Self::Unobservable => "unobservable",
            Self::MaturityStaked => "maturity_staked",
            Self::DissolveChanged => "dissolve_changed",
            Self::ControlChanged => "control_changed",
            Self::AutoStakeChanged => "auto_stake_changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub detail: String,
}

fn ev(kind: EventKind, detail: impl Into<String>) -> Event {
    Event {
        kind,
        detail: detail.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeuronInterval {
    pub neuron_id: u64,
    pub comparable: bool,
    /// Increase of maturity + staked maturity; 0 unless `comparable`.
    pub earned_e8s: u128,
    /// Effective stake (cached - fees) + staked maturity at interval start; 0 unless `comparable`.
    pub base_e8s: u128,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntervalStatus {
    Valid,
    /// Shorter than the minimum interval; maturity accrual is too coarse to annualize.
    TooShort,
    /// No neuron was comparable (or none had a positive base).
    NoComparableBase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interval {
    pub from_unix: u64,
    pub to_unix: u64,
    pub secs: u64,
    pub status: IntervalStatus,
    pub neurons: Vec<NeuronInterval>,
    pub comparable_count: usize,
    pub excluded_count: usize,
    pub earned_e8s: u128,
    pub base_e8s: u128,
    /// Simple annualized rate in ppm; only for `Valid` intervals.
    pub apr_ppm: Option<u128>,
}

fn stake(r: &NeuronRecord) -> u64 {
    r.cached_stake_e8s.unwrap_or(0)
}
fn fees(r: &NeuronRecord) -> u64 {
    r.neuron_fees_e8s.unwrap_or(0)
}
fn maturity(r: &NeuronRecord) -> u64 {
    r.maturity_e8s.unwrap_or(0)
}
fn staked(r: &NeuronRecord) -> u64 {
    r.staked_maturity_e8s.unwrap_or(0)
}
fn effective_base(r: &NeuronRecord) -> u128 {
    stake(r).saturating_sub(fees(r)) as u128 + staked(r) as u128
}

fn index(s: &Snapshot) -> BTreeMap<u64, &NeuronRecord> {
    s.neurons
        .iter()
        .filter_map(|r| r.id().map(|id| (id, r)))
        .collect()
}

fn non_comparable(id: u64, events: Vec<Event>) -> NeuronInterval {
    NeuronInterval {
        neuron_id: id,
        comparable: false,
        earned_e8s: 0,
        base_e8s: 0,
        events,
    }
}

fn compare_neuron(
    id: u64,
    a: Option<&NeuronRecord>,
    b: Option<&NeuronRecord>,
    at_a: u64,
    at_b: u64,
) -> Option<NeuronInterval> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => b.is_full().then(|| {
            non_comparable(
                id,
                vec![ev(EventKind::NewNeuron, "not in the earlier inventory")],
            )
        }),
        (Some(a), None) => a.is_full().then(|| {
            non_comparable(
                id,
                vec![ev(
                    EventKind::MissingNeuron,
                    "no longer in the inventory of the later snapshot",
                )],
            )
        }),
        (Some(a), Some(b)) => match (a.is_full(), b.is_full()) {
            (true, true) => Some(compare_both(id, a, b, at_a, at_b)),
            (true, false) if b.status == Status::NotFound => Some(non_comparable(
                id,
                vec![ev(
                    EventKind::MissingNeuron,
                    format!(
                        "last seen with {} e8s stake; no longer returned by Governance \
                         (removed, e.g. fully disbursed, or no longer readable)",
                        stake(a)
                    ),
                )],
            )),
            (true, false) => Some(non_comparable(
                id,
                vec![ev(
                    EventKind::Unobservable,
                    format!("later snapshot status is {:?}", b.status),
                )],
            )),
            (false, true) if a.status == Status::NotFound => Some(non_comparable(
                id,
                vec![ev(
                    EventKind::NewNeuron,
                    "not returned by Governance in the earlier snapshot",
                )],
            )),
            (false, true) => Some(non_comparable(
                id,
                vec![ev(
                    EventKind::Unobservable,
                    format!("earlier snapshot status was {:?}", a.status),
                )],
            )),
            (false, false) => None,
        },
    }
}

fn compare_both(
    id: u64,
    a: &NeuronRecord,
    b: &NeuronRecord,
    at_a: u64,
    at_b: u64,
) -> NeuronInterval {
    let mut events = vec![];
    let (sa, sb) = (stake(a), stake(b));
    if sb > sa {
        events.push(ev(
            EventKind::StakeIncrease,
            format!("cached stake +{} e8s (top-up, merge or refresh)", sb - sa),
        ));
    } else if sb < sa {
        if sb == 0 {
            events.push(ev(
                EventKind::PossibleDisbursement,
                format!("cached stake {sa} -> 0 e8s"),
            ));
        } else {
            events.push(ev(
                EventKind::StakeDecrease,
                format!(
                    "cached stake -{} e8s (split or partial disbursement)",
                    sa - sb
                ),
            ));
        }
    }
    if fees(a) != fees(b) {
        events.push(ev(
            EventKind::FeesChanged,
            format!("neuron fees {} -> {} e8s", fees(a), fees(b)),
        ));
    }
    let (tot_a, tot_b) = (
        maturity(a) as u128 + staked(a) as u128,
        maturity(b) as u128 + staked(b) as u128,
    );
    if tot_b < tot_a {
        events.push(ev(
            EventKind::MaturityOutflow,
            format!(
                "maturity + staked maturity fell by {} e8s (spawn, maturity disbursement or merge)",
                tot_a - tot_b
            ),
        ));
    } else if staked(b) < staked(a) {
        events.push(ev(
            EventKind::UnexplainedMovement,
            "staked maturity decreased while the total did not",
        ));
    } else if staked(b) > staked(a) && maturity(b) < maturity(a) {
        events.push(ev(
            EventKind::MaturityStaked,
            format!(
                "maturity -> staked maturity conversion observed (staked +{} e8s)",
                staked(b) - staked(a)
            ),
        ));
    }
    if dissolve_class(a, at_a) != dissolve_class(b, at_b) {
        events.push(ev(
            EventKind::DissolveChanged,
            format!(
                "{} -> {}",
                dissolve_class(a, at_a).name(),
                dissolve_class(b, at_b).name()
            ),
        ));
    }
    let hot = |r: &NeuronRecord| {
        let mut h = r.hot_keys.clone();
        h.sort();
        h
    };
    if a.controller != b.controller || hot(a) != hot(b) {
        events.push(ev(
            EventKind::ControlChanged,
            "controller or hotkeys differ",
        ));
    }
    if a.auto_stake_maturity != b.auto_stake_maturity {
        events.push(ev(
            EventKind::AutoStakeChanged,
            format!("{:?} -> {:?}", a.auto_stake_maturity, b.auto_stake_maturity),
        ));
    }
    let comparable = !events.iter().any(|e| e.kind.breaks_comparability());
    NeuronInterval {
        neuron_id: id,
        comparable,
        earned_e8s: if comparable { tot_b - tot_a } else { 0 },
        base_e8s: if comparable { effective_base(a) } else { 0 },
        events,
    }
}

/// Simple annualized rate: earned / (base * secs) * year, in ppm. `None` on zero base or overflow.
pub fn annualize_ppm(earned: u128, base_seconds: u128) -> Option<u128> {
    if base_seconds == 0 {
        return None;
    }
    earned
        .checked_mul(YEAR_SECS)?
        .checked_mul(PPM)?
        .checked_div(base_seconds)
}

/// Compound APY in ppm, assuming `COMPOUNDING_PERIODS` equal compounding steps per year at the
/// given APR (fixed-point, truncating). `None` on overflow.
pub fn compound_apy_ppm(apr_ppm: u128) -> Option<u128> {
    let growth =
        SCALE.checked_add(apr_ppm.checked_mul(SCALE / PPM)? / COMPOUNDING_PERIODS as u128)?;
    let (mut result, mut base, mut exp) = (SCALE, growth, COMPOUNDING_PERIODS);
    while exp > 0 {
        if exp & 1 == 1 {
            result = result.checked_mul(base)? / SCALE;
        }
        exp >>= 1;
        if exp > 0 {
            base = base.checked_mul(base)? / SCALE;
        }
    }
    Some(result.saturating_sub(SCALE) / (SCALE / PPM))
}

pub fn compare(a: &Snapshot, b: &Snapshot, min_secs: u64) -> Result<Interval, String> {
    if b.taken_at_unix <= a.taken_at_unix {
        return Err(format!(
            "snapshots are not in chronological order ({} >= {})",
            a.taken_at_unix, b.taken_at_unix
        ));
    }
    let secs = b.taken_at_unix - a.taken_at_unix;
    let (ia, ib) = (index(a), index(b));
    let ids: BTreeSet<u64> = ia.keys().chain(ib.keys()).copied().collect();
    let neurons: Vec<NeuronInterval> = ids
        .into_iter()
        .filter_map(|id| {
            compare_neuron(
                id,
                ia.get(&id).copied(),
                ib.get(&id).copied(),
                a.taken_at_unix,
                b.taken_at_unix,
            )
        })
        .collect();
    let comparable_count = neurons.iter().filter(|n| n.comparable).count();
    let excluded_count = neurons.len() - comparable_count;
    let earned_e8s: u128 = neurons.iter().map(|n| n.earned_e8s).sum();
    let base_e8s: u128 = neurons.iter().map(|n| n.base_e8s).sum();
    let status = if secs < min_secs {
        IntervalStatus::TooShort
    } else if base_e8s == 0 {
        IntervalStatus::NoComparableBase
    } else {
        IntervalStatus::Valid
    };
    let apr_ppm = (status == IntervalStatus::Valid)
        .then(|| annualize_ppm(earned_e8s, base_e8s * secs as u128))
        .flatten();
    Ok(Interval {
        from_unix: a.taken_at_unix,
        to_unix: b.taken_at_unix,
        secs,
        status,
        neurons,
        comparable_count,
        excluded_count,
        earned_e8s,
        base_e8s,
        apr_ppm,
    })
}

/// Protocol revenue derived from observed rewards. This is a *gross share estimate*:
/// it excludes affiliate/referral fees and is not a measurement of fees actually collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revenue {
    pub share_bps: u32,
    /// Gross share of the rewards observed over the valid intervals.
    pub observed_gross_e8s: u128,
    pub projected_monthly_gross_e8s: u128,
    pub projected_annual_gross_e8s: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aggregate {
    pub valid_intervals: usize,
    pub span_secs: u128,
    pub earned_e8s: u128,
    /// Time-weighted: sum(earned) / sum(base * secs) annualized. Realized from snapshots.
    pub observed_apr_ppm: Option<u128>,
    /// Projection only: observed APR compounded `COMPOUNDING_PERIODS` times a year.
    pub projected_apy_ppm: Option<u128>,
    /// Observed earnings on the comparable neurons, scaled linearly to one month.
    pub monthly_observed_e8s: u128,
    /// Latest-snapshot base (all fully readable neurons) times observed APR / 12. Projection.
    pub current_base_e8s: u128,
    pub projected_monthly_on_current_base_e8s: Option<u128>,
    pub revenue: Revenue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    pub snapshot_count: usize,
    pub intervals: Vec<Interval>,
    pub warnings: Vec<String>,
    /// Set when no return may be computed at all.
    pub insufficient: Option<String>,
    pub aggregate: Option<Aggregate>,
}

pub fn analyze(snaps: &[&Snapshot], min_secs: u64, share_bps: u32) -> History {
    let mut h = History {
        snapshot_count: snaps.len(),
        intervals: vec![],
        warnings: vec![],
        insufficient: None,
        aggregate: None,
    };
    if snaps.len() < 2 {
        h.insufficient = Some(format!(
            "INSUFFICIENT HISTORY: {} snapshot(s); at least 2 are required. No return was computed.",
            snaps.len()
        ));
        return h;
    }
    for w in snaps.windows(2) {
        match compare(w[0], w[1], min_secs) {
            Ok(i) => h.intervals.push(i),
            Err(e) => h.warnings.push(e),
        }
    }
    let valid: Vec<&Interval> = h
        .intervals
        .iter()
        .filter(|i| i.status == IntervalStatus::Valid)
        .collect();
    if valid.is_empty() {
        h.insufficient = Some(
            "INSUFFICIENT COMPARABLE HISTORY: no interval is long enough and free of unexplained \
             movements. No return was computed."
                .into(),
        );
        return h;
    }
    let earned: u128 = valid.iter().map(|i| i.earned_e8s).sum();
    let base_seconds: u128 = valid.iter().map(|i| i.base_e8s * i.secs as u128).sum();
    let span: u128 = valid.iter().map(|i| i.secs as u128).sum();
    let apr = annualize_ppm(earned, base_seconds);
    let latest = snaps[snaps.len() - 1];
    let current_base: u128 = latest
        .neurons
        .iter()
        .filter(|r| r.is_full())
        .map(effective_base)
        .sum();
    let annual_observed = earned.saturating_mul(YEAR_SECS) / span;
    let bps = share_bps as u128;
    h.aggregate = Some(Aggregate {
        valid_intervals: valid.len(),
        span_secs: span,
        earned_e8s: earned,
        observed_apr_ppm: apr,
        projected_apy_ppm: apr.and_then(compound_apy_ppm),
        monthly_observed_e8s: earned.saturating_mul(MONTH_SECS) / span,
        current_base_e8s: current_base,
        projected_monthly_on_current_base_e8s: apr
            .and_then(|a| current_base.checked_mul(a))
            .map(|v| v / (PPM * 12)),
        revenue: Revenue {
            share_bps,
            observed_gross_e8s: earned.saturating_mul(bps) / 10_000,
            projected_monthly_gross_e8s: earned.saturating_mul(MONTH_SECS).saturating_mul(bps)
                / span
                / 10_000,
            projected_annual_gross_e8s: annual_observed.saturating_mul(bps) / 10_000,
        },
    });
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::tests::{full, snap};
    use crate::snapshot::DissolveRec;

    const DAY: u64 = 86_400;
    const T0: u64 = 1_700_000_000;
    const ICP: u64 = 100_000_000;

    fn kinds(i: &Interval, id: u64) -> Vec<EventKind> {
        i.neurons
            .iter()
            .find(|n| n.neuron_id == id)
            .unwrap()
            .events
            .iter()
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn single_snapshot_is_insufficient() {
        let s = snap(T0, vec![full(1, 1000 * ICP, 0, 0, 0)]);
        let h = analyze(&[&s], DAY, 1000);
        assert!(h
            .insufficient
            .as_ref()
            .unwrap()
            .contains("INSUFFICIENT HISTORY"));
        assert!(h.aggregate.is_none());
        assert!(h.intervals.is_empty());
    }

    #[test]
    fn exact_apr_monthly_and_revenue() {
        // 1000 ICP base earns 0.1 ICP in one day.
        let a = snap(T0, vec![full(1, 1000 * ICP, 0, 0, 0)]);
        let b = snap(T0 + DAY, vec![full(1, 1000 * ICP, 0, ICP / 10, 0)]);
        let h = analyze(&[&a, &b], DAY, 1000);
        let i = &h.intervals[0];
        assert_eq!(i.status, IntervalStatus::Valid);
        assert_eq!((i.earned_e8s, i.base_e8s), (10_000_000, 1000 * ICP as u128));
        assert_eq!(i.apr_ppm, Some(36_525)); // 3.6525 %
        let g = h.aggregate.unwrap();
        assert_eq!(g.observed_apr_ppm, Some(36_525));
        assert_eq!(g.monthly_observed_e8s, 304_375_000); // 3.04375 ICP
        assert_eq!(g.current_base_e8s, 1000 * ICP as u128);
        // 1000 ICP * 3.6525% / 12 = 3.04375 ICP
        assert_eq!(g.projected_monthly_on_current_base_e8s, Some(304_375_000));
        assert_eq!(g.revenue.observed_gross_e8s, 1_000_000);
        assert_eq!(g.revenue.projected_monthly_gross_e8s, 30_437_500);
        assert_eq!(g.revenue.projected_annual_gross_e8s, 365_250_000);
        let apy = g.projected_apy_ppm.unwrap();
        assert!(apy > 36_525 && apy < 37_500, "{apy}");
    }

    #[test]
    fn compound_apy_matches_reference() {
        // (1 + 0.10/365)^365 - 1 = 10.5155...%
        let apy = compound_apy_ppm(100_000).unwrap();
        assert!((105_150..=105_160).contains(&apy), "{apy}");
        assert_eq!(compound_apy_ppm(0), Some(0));
        assert!(compound_apy_ppm(u128::MAX / 2).is_none());
    }

    #[test]
    fn annualize_guards() {
        assert_eq!(annualize_ppm(1, 0), None);
        assert_eq!(annualize_ppm(0, 5), Some(0));
        assert_eq!(annualize_ppm(u128::MAX, 1), None);
    }

    #[test]
    fn maturity_to_staked_conversion_is_not_an_outflow() {
        // 5 ICP of maturity staked, plus 0.2 ICP of fresh rewards.
        let a = snap(T0, vec![full(1, 100 * ICP, 0, 5 * ICP, ICP)]);
        let b = snap(T0 + DAY, vec![full(1, 100 * ICP, 0, 0, 6 * ICP + ICP / 5)]);
        let i = compare(&a, &b, DAY).unwrap();
        assert!(i.neurons[0].comparable);
        assert_eq!(i.earned_e8s, (ICP / 5) as u128);
        assert_eq!(kinds(&i, 1), vec![EventKind::MaturityStaked]);
        assert_eq!(i.base_e8s, (101 * ICP) as u128); // stake + staked maturity at start
    }

    #[test]
    fn unexplained_movements_are_excluded_not_counted_as_rewards() {
        let a = snap(
            T0,
            vec![
                full(1, 100 * ICP, 0, 0, 0),       // clean: +1 ICP
                full(2, 100 * ICP, 0, 0, 0),       // stake top-up
                full(3, 100 * ICP, 0, 9 * ICP, 0), // maturity spent
                full(4, 100 * ICP, 0, 0, 0),       // stake emptied
                full(5, 100 * ICP, 0, 0, 0),       // fee charged
                full(6, 100 * ICP, 0, 0, 0),       // vanishes
                full(7, 100 * ICP, 0, 0, 0),       // stake partly withdrawn
            ],
        );
        let b = snap(
            T0 + DAY,
            vec![
                full(1, 100 * ICP, 0, ICP, 0),
                full(2, 150 * ICP, 0, ICP, 0),
                full(3, 100 * ICP, 0, 2 * ICP, 0),
                full(4, 0, 0, 3 * ICP, 0),
                full(5, 100 * ICP, 1, ICP, 0),
                {
                    let mut r = crate::snapshot::NeuronRecord::blank(6, Status::NotFound);
                    r.error = None;
                    r
                },
                full(7, 60 * ICP, 0, ICP, 0),
                full(8, 10 * ICP, 0, 0, 0), // new
            ],
        );
        let i = compare(&a, &b, DAY).unwrap();
        assert_eq!(i.comparable_count, 1);
        assert_eq!(i.excluded_count, 7);
        assert_eq!(i.earned_e8s, ICP as u128, "only the clean neuron counts");
        assert_eq!(i.base_e8s, (100 * ICP) as u128);
        assert_eq!(kinds(&i, 2), vec![EventKind::StakeIncrease]);
        assert_eq!(kinds(&i, 3), vec![EventKind::MaturityOutflow]);
        assert_eq!(kinds(&i, 4), vec![EventKind::PossibleDisbursement]);
        assert_eq!(kinds(&i, 5), vec![EventKind::FeesChanged]);
        assert_eq!(kinds(&i, 6), vec![EventKind::MissingNeuron]);
        assert_eq!(kinds(&i, 7), vec![EventKind::StakeDecrease]);
        assert_eq!(kinds(&i, 8), vec![EventKind::NewNeuron]);
    }

    #[test]
    fn informational_events_keep_comparability() {
        let a = snap(T0, vec![full(1, 100 * ICP, 0, 0, 0)]);
        let mut n = full(1, 100 * ICP, 0, ICP, 0);
        n.dissolve = Some(DissolveRec::WhenDissolvedTimestampSeconds(T0 + 30 * DAY));
        n.hot_keys = vec!["aaaaa-aa".into()];
        n.auto_stake_maturity = Some(true);
        let b = snap(T0 + DAY, vec![n]);
        let i = compare(&a, &b, DAY).unwrap();
        assert!(i.neurons[0].comparable);
        assert_eq!(
            kinds(&i, 1),
            vec![
                EventKind::DissolveChanged,
                EventKind::ControlChanged,
                EventKind::AutoStakeChanged
            ]
        );
    }

    #[test]
    fn unreadable_snapshots_are_unobservable() {
        let a = snap(
            T0,
            vec![full(1, 100 * ICP, 0, 0, 0), full(2, 100 * ICP, 0, 0, 0)],
        );
        let b = snap(
            T0 + DAY,
            vec![
                crate::snapshot::NeuronRecord::blank(1, Status::InfoOnly),
                crate::snapshot::NeuronRecord::blank(2, Status::NotQueried),
            ],
        );
        let i = compare(&a, &b, DAY).unwrap();
        assert_eq!(i.comparable_count, 0);
        assert_eq!(kinds(&i, 1), vec![EventKind::Unobservable]);
        assert_eq!(kinds(&i, 2), vec![EventKind::Unobservable]);
        assert_eq!(i.status, IntervalStatus::NoComparableBase);
        let h = analyze(&[&a, &b], DAY, 1000);
        assert!(h
            .insufficient
            .unwrap()
            .contains("INSUFFICIENT COMPARABLE HISTORY"));
    }

    #[test]
    fn short_interval_yields_no_return() {
        let a = snap(T0, vec![full(1, 100 * ICP, 0, 0, 0)]);
        let b = snap(T0 + 3_600, vec![full(1, 100 * ICP, 0, 1_000, 0)]);
        let i = compare(&a, &b, DAY).unwrap();
        assert_eq!(i.status, IntervalStatus::TooShort);
        assert_eq!(i.apr_ppm, None);
        assert!(analyze(&[&a, &b], DAY, 1000).aggregate.is_none());
    }

    #[test]
    fn aggregate_is_time_weighted_and_skips_invalid_intervals() {
        let a = snap(T0, vec![full(1, 1000 * ICP, 0, 0, 0)]);
        let b = snap(T0 + DAY, vec![full(1, 1000 * ICP, 0, ICP / 10, 0)]);
        // Interval b -> c has a top-up and is non-comparable for neuron 1.
        let c = snap(T0 + 2 * DAY, vec![full(1, 1100 * ICP, 0, ICP / 5, 0)]);
        // Interval c -> d is clean again (2 days, 0.4 ICP on 1100 ICP).
        let d = snap(
            T0 + 4 * DAY,
            vec![full(1, 1100 * ICP, 0, ICP / 5 + 40_000_000, 0)],
        );
        let h = analyze(&[&a, &b, &c, &d], DAY, 1000);
        assert_eq!(h.intervals.len(), 3);
        assert_eq!(h.intervals[1].status, IntervalStatus::NoComparableBase);
        let g = h.aggregate.unwrap();
        assert_eq!(g.valid_intervals, 2);
        assert_eq!(g.earned_e8s, 10_000_000 + 40_000_000);
        // sum(base*secs) = 1000 ICP * 1d + 1100 ICP * 2d
        let expected = annualize_ppm(
            50_000_000,
            (1000 * ICP as u128) * DAY as u128 + (1100 * ICP as u128) * 2 * DAY as u128,
        );
        assert_eq!(g.observed_apr_ppm, expected);
        assert_eq!(g.span_secs, 3 * DAY as u128);
    }

    #[test]
    fn out_of_order_snapshots_are_reported() {
        let a = snap(T0, vec![]);
        let b = snap(T0, vec![]);
        assert!(compare(&a, &b, DAY).is_err());
        let h = analyze(&[&a, &b], DAY, 1000);
        assert_eq!(h.warnings.len(), 1);
        assert!(h.insufficient.is_some());
    }
}
