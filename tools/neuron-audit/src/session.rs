//! Shared setup for the authenticated commands (`inspect`, `audit`).

use crate::{identity, owner, signer};
use anyhow::{anyhow, bail, Context, Result};
use candid::Principal;
use ic_agent::{Agent, Identity};
use std::{path::Path, sync::Arc};

pub struct Preflight {
    pub owner_agent: Agent,
}

/// Local-only PEM check, then the free `get_all_owners` query. Signs nothing on the network
/// except the owner's own (free) query envelope.
pub async fn preflight(
    owner_pem: &Path,
    expected_owner: Principal,
    signing: Principal,
    ic_url: &str,
) -> Result<Preflight> {
    let owner_identity = owner::load_owner_identity(owner_pem)?;
    let owner = owner_identity.sender().map_err(|e| anyhow!(e))?;
    if owner != expected_owner {
        bail!("owner PEM principal {owner} != expected owner {expected_owner}; aborting");
    }
    println!("Owner identity   : {owner} (matches expected)");

    let owner_agent = Agent::builder()
        .with_url(ic_url.to_string())
        .with_boxed_identity(owner_identity)
        .build()?;
    let bytes = owner_agent
        .query(&signing, "get_all_owners")
        .with_arg(candid::encode_args(())?)
        .call()
        .await
        .context("signing.get_all_owners failed")?;
    let owners: Vec<Principal> = candid::decode_one(&bytes)?;
    println!(
        "Signing owners   : {}",
        owners
            .iter()
            .map(|p| p.to_text())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !owners.contains(&owner) {
        bail!("{owner} is not an owner of the signing canister; signing would be rejected");
    }
    Ok(Preflight { owner_agent })
}

pub struct OracleSession {
    pub agent: Agent,
    pub identity: Arc<signer::OracleIdentity>,
    pub principal: Principal,
}

/// Re-derives the Oracle principal from the live signing canister and aborts, before any
/// signature, if it differs from `expected`.
pub async fn connect_oracle(
    pre: Preflight,
    signing: Principal,
    governance: Principal,
    expected: Principal,
    ic_url: &str,
    max_signatures: u32,
) -> Result<OracleSession> {
    connect_oracle_with(
        pre,
        signing,
        governance,
        expected,
        ic_url,
        max_signatures,
        None,
    )
    .await
}

/// Like `connect_oracle`, optionally authorizing one exact `manage_neuron` payload.
pub async fn connect_oracle_with(
    pre: Preflight,
    signing: Principal,
    governance: Principal,
    expected: Principal,
    ic_url: &str,
    max_signatures: u32,
    authorized_manage_neuron: Option<Vec<u8>>,
) -> Result<OracleSession> {
    connect_oracle_inner(
        pre,
        signing,
        governance,
        expected,
        ic_url,
        max_signatures,
        authorized_manage_neuron,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_oracle_inner(
    pre: Preflight,
    signing: Principal,
    governance: Principal,
    expected: Principal,
    ic_url: &str,
    max_signatures: u32,
    authorized_manage_neuron: Option<Vec<u8>>,
    start_only: bool,
) -> Result<OracleSession> {
    let reply = pre
        .owner_agent
        .update(&signing, "public_key")
        .with_arg(candid::encode_args(())?)
        .call_and_wait()
        .await
        .context("signing.public_key failed")?;
    let sec1 = identity::decode_public_key_reply(&reply).map_err(|e| anyhow!(e))?;
    let principal = identity::principal_from_sec1(&sec1).map_err(|e| anyhow!(e))?;
    println!("Oracle principal : {principal}");
    if principal != expected {
        bail!("Oracle principal {principal} != expected {expected}; aborting before any signature");
    }

    let backend = Arc::new(signer::CanisterSigner {
        owner_agent: pre.owner_agent,
        signing_canister: signing,
        handle: tokio::runtime::Handle::current(),
    });
    let mut oracle = signer::OracleIdentity::new(&sec1, governance, backend, max_signatures)
        .map_err(|e| anyhow!(e))?;
    if let Some(arg) = authorized_manage_neuron {
        oracle = if start_only {
            oracle.with_authorized_start_dissolving(arg)
        } else {
            oracle.with_authorized_manage_neuron(arg)
        };
    }
    let identity = Arc::new(oracle);
    let agent = Agent::builder()
        .with_url(ic_url.to_string())
        .with_arc_identity(identity.clone())
        .build()?;
    Ok(OracleSession {
        agent,
        identity,
        principal,
    })
}

/// Connects an identity whose sole update permission is one validated StartDissolving payload.
pub async fn connect_oracle_for_dissolve(
    pre: Preflight,
    signing: Principal,
    governance: Principal,
    expected: Principal,
    ic_url: &str,
    max_signatures: u32,
    payload: Vec<u8>,
) -> Result<OracleSession> {
    if !crate::dissolve::is_start_payload(&payload) {
        bail!("refusing non-StartDissolving payload");
    }
    connect_oracle_inner(
        pre,
        signing,
        governance,
        expected,
        ic_url,
        max_signatures,
        Some(payload),
        true,
    )
    .await
}
