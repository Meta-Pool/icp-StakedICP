//! Batched, budgeted collection of neuron records. The network call is injected so the logic
//! is testable with fixtures; the real fetcher (a signed Governance `list_neurons` query)
//! lives in `main.rs`.

use crate::governance::ListNeuronsResponse;
use crate::snapshot::{NeuronRecord, Status};
use anyhow::{bail, Result};
use candid::Principal;
use std::future::Future;

/// Signatures reserved for the agent's own `read_state` lookups (subnet node keys used to
/// verify query responses). Query signing itself costs exactly one signature per batch.
pub const READ_STATE_OVERHEAD: u32 = 2;
/// ECDSA cycles attached by `signing.sign` per signature (src/signing/src/lib.rs).
pub const CYCLES_PER_SIGNATURE: u64 = 26_153_846_153;

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub batches: Vec<Vec<u64>>,
    pub required_signatures: u32,
}

pub fn plan(ids: &[u64], batch_size: usize) -> Plan {
    let batches: Vec<Vec<u64>> = ids.chunks(batch_size.max(1)).map(|c| c.to_vec()).collect();
    let required_signatures = batches.len() as u32 + READ_STATE_OVERHEAD;
    Plan {
        batches,
        required_signatures,
    }
}

pub fn check_budget(plan: &Plan, budget: u32) -> Result<()> {
    if budget < plan.required_signatures {
        bail!(
            "signature budget {budget} is below the {} needed ({} batches + {READ_STATE_OVERHEAD} read_state); \
             raise --max-signatures or --batch-size",
            plan.required_signatures,
            plan.batches.len()
        );
    }
    Ok(())
}

#[derive(Debug)]
pub struct Collected {
    pub records: Vec<NeuronRecord>,
    pub batches_completed: usize,
    pub complete: bool,
}

/// Queries every batch in order. The first failed batch stops the run: its neurons are marked
/// `query_failed`, all later ones `not_queried`, so no ID is ever assumed accessible.
pub async fn collect<F, Fut>(batches: &[Vec<u64>], oracle: &Principal, mut fetch: F) -> Collected
where
    F: FnMut(Vec<u64>) -> Fut,
    Fut: Future<Output = Result<ListNeuronsResponse, String>>,
{
    let mut records = Vec::new();
    let mut completed = 0;
    let mut failed = false;
    for batch in batches {
        if failed {
            records.extend(
                batch
                    .iter()
                    .map(|id| NeuronRecord::blank(*id, Status::NotQueried)),
            );
            continue;
        }
        match fetch(batch.clone()).await {
            Ok(resp) => {
                completed += 1;
                for id in batch {
                    let full = resp
                        .full_neurons
                        .iter()
                        .find(|n| n.id.as_ref().map(|i| i.id) == Some(*id));
                    let info = resp
                        .neuron_infos
                        .iter()
                        .find(|(i, _)| i == id)
                        .map(|(_, v)| v);
                    records.push(NeuronRecord::from_response(*id, full, info, oracle));
                }
            }
            Err(e) => {
                failed = true;
                records.extend(batch.iter().map(|id| {
                    let mut r = NeuronRecord::blank(*id, Status::QueryFailed);
                    r.error = Some(e.clone());
                    r
                }));
            }
        }
    }
    Collected {
        records,
        batches_completed: completed,
        complete: !failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{DissolveState, Neuron, NeuronId, NeuronInfo};
    use crate::snapshot::Status;

    fn oracle() -> Principal {
        Principal::from_text("xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe")
            .unwrap()
    }

    fn info(stake: u64) -> NeuronInfo {
        NeuronInfo {
            dissolve_delay_seconds: 1,
            state: 1,
            stake_e8s: stake,
            created_timestamp_seconds: 0,
            age_seconds: 0,
            voting_power: 0,
            retrieved_at_timestamp_seconds: 0,
        }
    }

    fn neuron(id: u64, stake: u64) -> Neuron {
        Neuron {
            id: Some(NeuronId { id }),
            controller: Some(oracle()),
            hot_keys: vec![],
            cached_neuron_stake_e8s: stake,
            neuron_fees_e8s: 0,
            maturity_e8s_equivalent: 0,
            staked_maturity_e8s_equivalent: None,
            auto_stake_maturity: None,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(10)),
            aging_since_timestamp_seconds: 0,
            created_timestamp_seconds: 0,
            spawn_at_timestamp_seconds: None,
        }
    }

    #[test]
    fn plan_and_budget() {
        let ids: Vec<u64> = (1..=57).collect();
        let p = plan(&ids, 10);
        assert_eq!(p.batches.len(), 6);
        assert_eq!(p.batches.last().unwrap().len(), 7);
        assert_eq!(p.required_signatures, 6 + READ_STATE_OVERHEAD);
        assert!(check_budget(&p, 8).is_ok());
        assert!(check_budget(&p, 7)
            .unwrap_err()
            .to_string()
            .contains("below"));
        assert_eq!(plan(&ids, 100).batches.len(), 1);
        assert_eq!(plan(&[], 10).batches.len(), 0);
        assert_eq!(plan(&ids, 0).batches.len(), 57); // batch size is clamped to 1
    }

    #[tokio::test]
    async fn never_assumes_requested_ids_are_accessible() {
        let batches = vec![vec![1, 2, 3]];
        let c = collect(&batches, &oracle(), |_ids| async {
            Ok(ListNeuronsResponse {
                neuron_infos: vec![(1, info(100)), (2, info(200))],
                full_neurons: vec![neuron(1, 100)],
            })
        })
        .await;
        assert!(c.complete);
        let st: Vec<Status> = c.records.iter().map(|r| r.status).collect();
        assert_eq!(st, vec![Status::Full, Status::InfoOnly, Status::NotFound]);
        assert_eq!(c.records[1].info_stake_e8s, Some(200));
        assert_eq!(c.records[1].cached_stake_e8s, None);
    }

    #[tokio::test]
    async fn failure_stops_remaining_batches_and_marks_them() {
        let batches = vec![vec![1], vec![2], vec![3]];
        let mut calls = 0;
        let c = collect(&batches, &oracle(), |_ids| {
            calls += 1;
            let n = calls;
            async move {
                if n == 1 {
                    Ok(ListNeuronsResponse {
                        neuron_infos: vec![],
                        full_neurons: vec![neuron(1, 5)],
                    })
                } else {
                    Err("signature cap reached (3)".to_string())
                }
            }
        })
        .await;
        assert!(!c.complete);
        assert_eq!(c.batches_completed, 1);
        assert_eq!(calls, 2, "no batch after the failure may be attempted");
        let st: Vec<Status> = c.records.iter().map(|r| r.status).collect();
        assert_eq!(
            st,
            vec![Status::Full, Status::QueryFailed, Status::NotQueried]
        );
        assert!(c.records[1].error.as_ref().unwrap().contains("cap"));
    }
}
