//! Minimal, read-only subset of the NNS Governance Candid types (`list_neurons` query only).
//! Fields absent here are ignored on decode; every field below is `opt` or present in all
//! known Governance versions.

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

pub const E8S: u64 = 100_000_000;
const DAY: u64 = 86_400;

#[derive(CandidType, Serialize)]
pub struct ListNeuronsArgs {
    pub neuron_ids: Vec<u64>,
    pub include_neurons_readable_by_caller: bool,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct NeuronId {
    pub id: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
pub enum DissolveState {
    DissolveDelaySeconds(u64),
    WhenDissolvedTimestampSeconds(u64),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct Neuron {
    pub id: Option<NeuronId>,
    pub controller: Option<Principal>,
    pub hot_keys: Vec<Principal>,
    pub cached_neuron_stake_e8s: u64,
    pub neuron_fees_e8s: u64,
    pub maturity_e8s_equivalent: u64,
    pub staked_maturity_e8s_equivalent: Option<u64>,
    pub auto_stake_maturity: Option<bool>,
    pub dissolve_state: Option<DissolveState>,
    pub aging_since_timestamp_seconds: u64,
    pub created_timestamp_seconds: u64,
    pub spawn_at_timestamp_seconds: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct NeuronInfo {
    pub dissolve_delay_seconds: u64,
    pub state: i32,
    pub stake_e8s: u64,
    pub created_timestamp_seconds: u64,
    pub age_seconds: u64,
    pub voting_power: u64,
    pub retrieved_at_timestamp_seconds: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ListNeuronsResponse {
    pub neuron_infos: Vec<(u64, NeuronInfo)>,
    pub full_neurons: Vec<Neuron>,
}

/// `include_neurons_readable_by_caller = false` keeps the request to exactly the given IDs.
pub fn encode_list_neurons_batch(neuron_ids: &[u64]) -> Result<Vec<u8>, candid::Error> {
    candid::encode_one(ListNeuronsArgs {
        neuron_ids: neuron_ids.to_vec(),
        include_neurons_readable_by_caller: false,
    })
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct GovernanceError {
    pub error_type: i32,
    pub error_message: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum FullNeuronResult {
    Ok(Neuron),
    Err(GovernanceError),
}

/// `get_full_neuron : (nat64) -> (Result_2) query`
pub fn encode_get_full_neuron(neuron_id: u64) -> Result<Vec<u8>, candid::Error> {
    candid::encode_one(neuron_id)
}

pub fn decode_get_full_neuron(bytes: &[u8]) -> Result<FullNeuronResult, candid::Error> {
    candid::decode_one(bytes)
}

pub fn encode_list_neurons(neuron_id: u64) -> Result<Vec<u8>, candid::Error> {
    encode_list_neurons_batch(&[neuron_id])
}

pub fn decode_list_neurons(bytes: &[u8]) -> Result<ListNeuronsResponse, candid::Error> {
    candid::decode_one(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// The Oracle principal is the neuron's controller: full authority.
    Controller,
    /// The Oracle principal is only a hotkey: can vote/follow, cannot disburse or dissolve.
    HotKeyOnly,
    /// Governance returned the full neuron but the Oracle is neither controller nor hotkey.
    ReadableWithoutAuthority,
    /// Only public `neuron_info` was returned, or nothing at all.
    NotReadable,
}

pub fn classify(neuron: Option<&Neuron>, oracle: &Principal) -> Access {
    match neuron {
        None => Access::NotReadable,
        Some(n) if n.controller.as_ref() == Some(oracle) => Access::Controller,
        Some(n) if n.hot_keys.contains(oracle) => Access::HotKeyOnly,
        Some(_) => Access::ReadableWithoutAuthority,
    }
}

pub fn fmt_e8s(e8s: u128) -> String {
    let unit = E8S as u128;
    format!("{}.{:08}", e8s / unit, e8s % unit)
}

pub fn fmt_icp(e8s: u64) -> String {
    fmt_e8s(e8s.into())
}

pub fn state_name(state: i32) -> &'static str {
    match state {
        1 => "LOCKED (not dissolving)",
        2 => "DISSOLVING",
        3 => "DISSOLVED",
        4 => "SPAWNING",
        _ => "UNSPECIFIED",
    }
}

/// `YYYYMMDDTHHMMSSZ` from unix seconds (sortable; used in snapshot file names).
pub fn fmt_compact_utc(secs: u64) -> String {
    let t = fmt_utc(secs); // "YYYY-MM-DD HH:MM:SS UTC"
    format!(
        "{}{}{}T{}{}{}Z",
        &t[0..4],
        &t[5..7],
        &t[8..10],
        &t[11..13],
        &t[14..16],
        &t[17..19]
    )
}

/// `YYYY-MM-DD HH:MM:SS UTC` from unix seconds.
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / DAY) as i64;
    let rem = secs % DAY;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn describe_dissolve(state: &Option<DissolveState>, now: u64) -> String {
    match state {
        None => "unknown (no dissolve_state returned)".into(),
        Some(DissolveState::DissolveDelaySeconds(0)) => "DISSOLVED (delay 0)".into(),
        Some(DissolveState::DissolveDelaySeconds(d)) => format!(
            "LOCKED, not dissolving; delay {d}s (~{} days); unlock date unknown until dissolving starts",
            d / DAY
        ),
        Some(DissolveState::WhenDissolvedTimestampSeconds(t)) if *t <= now => {
            format!("DISSOLVED since {}", fmt_utc(*t))
        }
        Some(DissolveState::WhenDissolvedTimestampSeconds(t)) => format!(
            "DISSOLVING; unlocks {} (in ~{} days)",
            fmt_utc(*t),
            (t - now) / DAY
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Principal {
        Principal::from_text(s).unwrap()
    }

    fn oracle() -> Principal {
        p("xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe")
    }

    fn neuron(controller: Option<Principal>, hot_keys: Vec<Principal>) -> Neuron {
        Neuron {
            id: Some(NeuronId { id: 1 }),
            controller,
            hot_keys,
            cached_neuron_stake_e8s: 12_345_678_901,
            neuron_fees_e8s: 0,
            maturity_e8s_equivalent: 5,
            staked_maturity_e8s_equivalent: None,
            auto_stake_maturity: None,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(86_400 * 365)),
            aging_since_timestamp_seconds: 0,
            created_timestamp_seconds: 0,
            spawn_at_timestamp_seconds: None,
        }
    }

    #[test]
    fn classification_distinguishes_controller_from_hotkey() {
        let other = p("pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe");
        assert_eq!(
            classify(Some(&neuron(Some(oracle()), vec![])), &oracle()),
            Access::Controller
        );
        assert_eq!(
            classify(Some(&neuron(Some(other), vec![oracle()])), &oracle()),
            Access::HotKeyOnly
        );
        assert_eq!(
            classify(Some(&neuron(Some(other), vec![])), &oracle()),
            Access::ReadableWithoutAuthority
        );
        assert_eq!(classify(None, &oracle()), Access::NotReadable);
        // Controller wins over hotkey.
        assert_eq!(
            classify(Some(&neuron(Some(oracle()), vec![oracle()])), &oracle()),
            Access::Controller
        );
    }

    #[test]
    fn formats_icp_exactly() {
        assert_eq!(fmt_icp(0), "0.00000000");
        assert_eq!(fmt_icp(1), "0.00000001");
        assert_eq!(fmt_icp(12_345_678_901), "123.45678901");
    }

    #[test]
    fn formats_large_sums_exactly() {
        assert_eq!(fmt_e8s(919_500_000_000), "9195.00000000");
        assert_eq!(fmt_e8s(u64::MAX as u128 * 10), "1844674407370.95516150");
    }

    #[test]
    fn batch_request_carries_all_ids_and_no_implicit_ones() {
        let bytes = encode_list_neurons_batch(&[3, 1, 2]).unwrap();
        #[derive(CandidType, Deserialize)]
        struct Back {
            neuron_ids: Vec<u64>,
            include_neurons_readable_by_caller: bool,
        }
        let back: Back = candid::decode_one(&bytes).unwrap();
        assert_eq!(back.neuron_ids, vec![3, 1, 2]);
        assert!(!back.include_neurons_readable_by_caller);
    }

    #[test]
    fn formats_utc() {
        assert_eq!(fmt_compact_utc(1_709_210_096), "20240229T123456Z");
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_utc(1_709_210_096), "2024-02-29 12:34:56 UTC");
        assert_eq!(fmt_utc(1_798_761_599), "2026-12-31 23:59:59 UTC");
    }

    #[test]
    fn describes_dissolve_states() {
        let now = 1_000_000;
        assert!(
            describe_dissolve(&Some(DissolveState::DissolveDelaySeconds(0)), now)
                .contains("DISSOLVED")
        );
        assert!(
            describe_dissolve(&Some(DissolveState::DissolveDelaySeconds(86_400 * 30)), now)
                .contains("LOCKED")
        );
        assert!(describe_dissolve(
            &Some(DissolveState::WhenDissolvedTimestampSeconds(now - 1)),
            now
        )
        .contains("DISSOLVED since"));
        assert!(describe_dissolve(
            &Some(DissolveState::WhenDissolvedTimestampSeconds(
                now + 86_400 * 2
            )),
            now
        )
        .contains("in ~2 days"));
        assert!(describe_dissolve(&None, now).contains("unknown"));
    }

    #[test]
    fn request_is_exactly_one_neuron() {
        let bytes = encode_list_neurons(436472328193651593).unwrap();
        #[derive(CandidType, Deserialize)]
        struct Back {
            neuron_ids: Vec<u64>,
            include_neurons_readable_by_caller: bool,
        }
        let back: Back = candid::decode_one(&bytes).unwrap();
        assert_eq!(back.neuron_ids, vec![436472328193651593]);
        assert!(!back.include_neurons_readable_by_caller);
    }

    #[test]
    fn decodes_response_ignoring_unknown_fields() {
        // Wire type with extra fields (as a newer Governance would send) and a missing opt field.
        #[derive(CandidType, Serialize)]
        struct WireNeuron {
            id: Option<NeuronIdW>,
            controller: Option<Principal>,
            hot_keys: Vec<Principal>,
            cached_neuron_stake_e8s: u64,
            neuron_fees_e8s: u64,
            maturity_e8s_equivalent: u64,
            aging_since_timestamp_seconds: u64,
            created_timestamp_seconds: u64,
            dissolve_state: Option<WireDissolve>,
            followees: Vec<(i32, Vec<u64>)>,
            visibility: Option<i32>,
        }
        #[derive(CandidType, Serialize)]
        struct NeuronIdW {
            id: u64,
        }
        #[derive(CandidType, Serialize)]
        enum WireDissolve {
            DissolveDelaySeconds(u64),
        }
        #[derive(CandidType, Serialize)]
        struct WireInfo {
            dissolve_delay_seconds: u64,
            state: i32,
            stake_e8s: u64,
            created_timestamp_seconds: u64,
            age_seconds: u64,
            voting_power: u64,
            retrieved_at_timestamp_seconds: u64,
            recent_ballots: Vec<u64>,
        }
        #[derive(CandidType, Serialize)]
        struct WireResp {
            neuron_infos: Vec<(u64, WireInfo)>,
            full_neurons: Vec<WireNeuron>,
            total_pages_available: Option<u64>,
        }
        let resp = WireResp {
            neuron_infos: vec![(
                7,
                WireInfo {
                    dissolve_delay_seconds: 10,
                    state: 1,
                    stake_e8s: 100,
                    created_timestamp_seconds: 1,
                    age_seconds: 2,
                    voting_power: 3,
                    retrieved_at_timestamp_seconds: 4,
                    recent_ballots: vec![],
                },
            )],
            full_neurons: vec![WireNeuron {
                id: Some(NeuronIdW { id: 7 }),
                controller: Some(oracle()),
                hot_keys: vec![],
                cached_neuron_stake_e8s: 100,
                neuron_fees_e8s: 3,
                maturity_e8s_equivalent: 9,
                aging_since_timestamp_seconds: 1,
                created_timestamp_seconds: 1,
                dissolve_state: Some(WireDissolve::DissolveDelaySeconds(10)),
                followees: vec![(0, vec![1])],
                visibility: Some(2),
            }],
            total_pages_available: Some(1),
        };
        let bytes = candid::encode_one(&resp).unwrap();
        let r = decode_list_neurons(&bytes).unwrap();
        assert_eq!(r.neuron_infos[0].0, 7);
        let n = &r.full_neurons[0];
        assert_eq!(n.controller, Some(oracle()));
        assert_eq!(n.neuron_fees_e8s, 3);
        assert_eq!(n.staked_maturity_e8s_equivalent, None);
        assert_eq!(
            n.dissolve_state,
            Some(DissolveState::DissolveDelaySeconds(10))
        );
    }
}
