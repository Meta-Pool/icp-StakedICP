//! Controlled, single-purpose StartDissolving workflow.
use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(CandidType, Deserialize)]
struct NeuronId {
    id: u64,
}
#[derive(CandidType, Deserialize)]
enum IdOrSubaccount {
    NeuronId(NeuronId),
}
#[derive(CandidType, Deserialize)]
struct StartDissolving {}
#[derive(CandidType, Deserialize)]
enum Operation {
    StartDissolving(StartDissolving),
}
#[derive(CandidType, Deserialize)]
struct Configure {
    operation: Option<Operation>,
}
#[derive(CandidType, Deserialize)]
enum Command {
    Configure(Configure),
}
#[derive(CandidType, Deserialize)]
struct ManageNeuron {
    neuron_id_or_subaccount: Option<IdOrSubaccount>,
    command: Option<Command>,
    id: Option<NeuronId>,
}

pub fn encode_start_dissolving(id: u64) -> anyhow::Result<Vec<u8>> {
    Ok(candid::encode_one(ManageNeuron {
        neuron_id_or_subaccount: Some(IdOrSubaccount::NeuronId(NeuronId { id })),
        command: Some(Command::Configure(Configure {
            operation: Some(Operation::StartDissolving(StartDissolving {})),
        })),
        id: None,
    })?)
}

pub fn is_start_payload(bytes: &[u8]) -> bool {
    candid::decode_one::<ManageNeuron>(bytes)
        .map(|m| {
            matches!(
                m.command,
                Some(Command::Configure(Configure {
                    operation: Some(Operation::StartDissolving(_))
                }))
            ) && matches!(m.neuron_id_or_subaccount, Some(IdOrSubaccount::NeuronId(_)))
                && m.id.is_none()
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: u32,
    pub created_at_unix: u64,
    pub governance: String,
    pub oracle_principal: String,
    pub ids_source: String,
    pub ids_sha256: String,
    pub eligible: Vec<Entry>,
    pub excluded: Vec<Excluded>,
    pub plan_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub neuron_id: String,
    pub stake_e8s: u64,
    pub maturity_e8s: u64,
    pub dissolve_delay_seconds: u64,
    pub expected_dissolve_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Excluded {
    pub neuron_id: String,
    pub reason: String,
}

pub fn make_plan(
    ids: &[u64],
    records: &[crate::snapshot::NeuronRecord],
    oracle: &Principal,
    governance: &str,
    source: &str,
    ids_sha256: &str,
    now: u64,
) -> Plan {
    let unique: BTreeSet<u64> = ids.iter().copied().collect();
    let mut eligible = vec![];
    let mut excluded = vec![];
    for id in unique {
        let Some(r) = records.iter().find(|r| r.id() == Some(id)) else {
            excluded.push(Excluded {
                neuron_id: id.to_string(),
                reason: "missing fresh response".into(),
            });
            continue;
        };
        let reason = if r.status != crate::snapshot::Status::Full {
            Some("info-only or unavailable; controller not verified")
        } else if r.spawn_at_timestamp_seconds.is_some() {
            Some("neuron is spawning")
        } else if r.controller.as_deref() != Some(&oracle.to_text()) {
            Some("verified controller mismatch")
        } else {
            match &r.dissolve {
                Some(crate::snapshot::DissolveRec::DelaySeconds(d)) if *d > 0 => None,
                Some(crate::snapshot::DissolveRec::DelaySeconds(_)) => Some("already dissolved"),
                Some(crate::snapshot::DissolveRec::WhenDissolvedTimestampSeconds(_)) => {
                    Some("already dissolving")
                }
                None => Some("dissolve state unknown"),
            }
        };
        if let Some(reason) = reason {
            excluded.push(Excluded {
                neuron_id: id.to_string(),
                reason: reason.into(),
            });
        } else {
            let d = match r.dissolve {
                Some(crate::snapshot::DissolveRec::DelaySeconds(d)) => d,
                _ => 0,
            };
            eligible.push(Entry {
                neuron_id: id.to_string(),
                stake_e8s: r.cached_stake_e8s.unwrap_or(0),
                maturity_e8s: r.maturity_e8s.unwrap_or(0),
                dissolve_delay_seconds: d,
                expected_dissolve_unix: now.saturating_add(d),
            });
        }
    }
    let mut p = Plan {
        schema_version: 1,
        created_at_unix: now,
        governance: governance.into(),
        oracle_principal: oracle.to_text(),
        ids_source: source.into(),
        ids_sha256: ids_sha256.into(),
        eligible,
        excluded,
        plan_sha256: String::new(),
    };
    let bytes = serde_json::to_vec(&(
        &p.schema_version,
        &p.created_at_unix,
        &p.governance,
        &p.oracle_principal,
        &p.ids_source,
        &p.ids_sha256,
        &p.eligible,
        &p.excluded,
    ))
    .unwrap_or_default();
    p.plan_sha256 = hex(&Sha256::digest(bytes));
    p
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn write_plan(path: &Path, p: &Plan) -> anyhow::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    use std::io::Write;
    f.write_all(&serde_json::to_vec_pretty(p)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}
pub fn load_plan(path: &Path) -> anyhow::Result<Plan> {
    let p: Plan = serde_json::from_slice(&fs::read(path)?)?;
    validate_plan(&p)?;
    Ok(p)
}
pub fn write_record(path: &Path, value: &serde_json::Value) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}
pub fn validate_plan(p: &Plan) -> anyhow::Result<()> {
    anyhow::ensure!(p.schema_version == 1, "unsupported plan schema");
    let mut c = p.clone();
    let expected = c.plan_sha256.clone();
    c.plan_sha256.clear();
    let bytes = serde_json::to_vec(&(
        &c.schema_version,
        &c.created_at_unix,
        &c.governance,
        &c.oracle_principal,
        &c.ids_source,
        &c.ids_sha256,
        &c.eligible,
        &c.excluded,
    ))?;
    anyhow::ensure!(
        hex(&Sha256::digest(bytes)) == expected,
        "plan hash mismatch"
    );
    Ok(())
}

#[derive(CandidType, Deserialize)]
struct GovError {
    error_type: i32,
    error_message: String,
}
/// Governance replies `Configure : record {}` (an empty record, not `null`).
#[derive(CandidType, Deserialize)]
struct ConfigureOk {}
#[derive(CandidType, Deserialize)]
enum ResultCommand {
    Error(GovError),
    Configure(ConfigureOk),
}
#[derive(CandidType, Deserialize)]
struct ManageResponse {
    command: Option<ResultCommand>,
}
pub fn decode_response(bytes: &[u8]) -> anyhow::Result<Result<(), String>> {
    let r: ManageResponse = candid::decode_one(bytes)?;
    match r.command {
        Some(ResultCommand::Configure(_)) => Ok(Ok(())),
        Some(ResultCommand::Error(e)) => Ok(Err(format!(
            "Governance error {}: {}",
            e.error_type, e.error_message
        ))),
        None => Ok(Err("missing command response".into())),
    }
}

/// Only the exact record produced by the old decoder bug may be reconciled.
pub fn is_reconcilable(v: &serde_json::Value) -> bool {
    v["outcome"] == "governance_rejected"
        && v["governance_result"] == "missing command response"
        && v["submission_error"].is_null()
}

pub fn submission_outcome(
    network_error: bool,
    governance_ok: bool,
    post_state_is_dissolving: bool,
) -> &'static str {
    if !network_error && governance_ok && post_state_is_dissolving {
        "verified_success"
    } else if !network_error && !governance_ok {
        "governance_rejected"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoding_is_single_configure_start_dissolving() {
        let b = encode_start_dissolving(42).unwrap();
        let a: ManageNeuron = candid::decode_one(&b).unwrap();
        assert!(matches!(
            a.command,
            Some(Command::Configure(Configure {
                operation: Some(Operation::StartDissolving(_))
            }))
        ));
        assert!(matches!(
            a.neuron_id_or_subaccount,
            Some(IdOrSubaccount::NeuronId(NeuronId { id: 42 }))
        ));
    }

    #[test]
    fn only_start_payload_passes_narrow_validator() {
        let payload = encode_start_dissolving(5).unwrap();
        assert!(is_start_payload(&payload));
        assert!(!is_start_payload(b"not candid"));
    }

    #[test]
    fn plan_deduplicates_and_excludes_non_controller_and_info_only() {
        let oracle =
            Principal::from_text("xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe")
                .unwrap();
        let rec = |id: u64,
                   status: crate::snapshot::Status,
                   controller: Option<String>,
                   dissolve: Option<crate::snapshot::DissolveRec>| {
            crate::snapshot::NeuronRecord {
                neuron_id: id.to_string(),
                status,
                access: if controller == Some(oracle.to_text()) {
                    crate::governance::Access::Controller
                } else {
                    crate::governance::Access::NotReadable
                },
                controller,
                hot_keys: vec![],
                cached_stake_e8s: Some(100),
                neuron_fees_e8s: Some(0),
                maturity_e8s: Some(3),
                staked_maturity_e8s: Some(0),
                auto_stake_maturity: None,
                dissolve,
                spawn_at_timestamp_seconds: None,
                aging_since_timestamp_seconds: None,
                created_timestamp_seconds: None,
                info_state: None,
                info_stake_e8s: None,
                info_dissolve_delay_seconds: None,
                error: None,
            }
        };
        let records = vec![
            rec(
                1,
                crate::snapshot::Status::Full,
                Some(oracle.to_text()),
                Some(crate::snapshot::DissolveRec::DelaySeconds(10)),
            ),
            rec(2, crate::snapshot::Status::InfoOnly, None, None),
        ];
        let p = make_plan(&[1, 1, 2, 3], &records, &oracle, "gov", "ids", "hash", 100);
        assert_eq!(p.eligible.len(), 1);
        assert_eq!(p.eligible[0].neuron_id, "1");
        assert_eq!(p.eligible[0].expected_dissolve_unix, 110);
        assert_eq!(p.excluded.len(), 2);
        assert!(p.excluded.iter().any(|x| x.neuron_id == "2"));
        assert!(p.excluded.iter().any(|x| x.neuron_id == "3"));
        validate_plan(&p).unwrap();
    }

    #[test]
    fn response_parser_distinguishes_success_and_governance_error() {
        // Mirrors nns-governance.did Command_1: Configure : record {}.
        #[derive(CandidType)]
        struct EmptyRecord {}
        #[derive(CandidType)]
        enum RespCommand {
            Error(GovError),
            Configure(EmptyRecord),
        }
        #[derive(CandidType)]
        struct Resp {
            command: Option<RespCommand>,
        }
        let ok = candid::encode_one(Resp {
            command: Some(RespCommand::Configure(EmptyRecord {})),
        })
        .unwrap();
        assert!(decode_response(&ok).unwrap().is_ok());
        let err = candid::encode_one(Resp {
            command: Some(RespCommand::Error(GovError {
                error_type: 3,
                error_message: "no".into(),
            })),
        })
        .unwrap();
        assert_eq!(
            decode_response(&err).unwrap().unwrap_err(),
            "Governance error 3: no"
        );
    }

    #[test]
    fn decodes_untyped_governance_reply_with_empty_record() {
        use candid::types::value::{IDLArgs, IDLField, IDLValue, VariantValue};
        use candid::types::Label;
        let configure = IDLValue::Variant(VariantValue(
            Box::new(IDLField {
                id: Label::Named("Configure".into()),
                val: IDLValue::Record(vec![]),
            }),
            0,
        ));
        let reply = IDLValue::Record(vec![IDLField {
            id: Label::Named("command".into()),
            val: IDLValue::Opt(Box::new(configure)),
        }]);
        let bytes = IDLArgs::new(&[reply]).to_bytes().unwrap();
        assert!(decode_response(&bytes).unwrap().is_ok());
    }

    #[test]
    fn only_known_misclassification_is_reconcilable() {
        let good = serde_json::json!({"outcome":"governance_rejected","governance_result":"missing command response","submission_error":null});
        assert!(is_reconcilable(&good));
        let real = serde_json::json!({"outcome":"governance_rejected","governance_result":"Governance error 3: no","submission_error":null});
        assert!(!is_reconcilable(&real));
        let unk = serde_json::json!({"outcome":"unknown","governance_result":"missing command response","submission_error":"x"});
        assert!(!is_reconcilable(&unk));
    }

    #[test]
    fn ambiguous_submission_never_becomes_success_without_reconciliation() {
        assert_eq!(submission_outcome(true, true, false), "unknown");
        assert_eq!(submission_outcome(true, true, true), "unknown");
        assert_eq!(submission_outcome(false, true, false), "unknown");
        assert_eq!(submission_outcome(false, true, true), "verified_success");
        assert_eq!(
            submission_outcome(false, false, false),
            "governance_rejected"
        );
    }

    #[test]
    fn journal_records_are_write_once() {
        let d = std::env::temp_dir().join(format!("dissolve-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let path = d.join("intent.json");
        let v = serde_json::json!({"status":"submitting"});
        write_record(&path, &v).unwrap();
        assert!(write_record(&path, &v).is_err());
        let _ = fs::remove_dir_all(d);
    }
}
