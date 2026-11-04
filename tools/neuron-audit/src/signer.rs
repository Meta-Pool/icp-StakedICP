//! `ic-agent` identity whose private key lives in the signing canister (threshold ECDSA).
//!
//! Safety properties enforced here, independent of the CLI:
//! * only `list_neurons` queries to the configured Governance canister, and `read_state`
//!   (used by the agent for subnet key lookup), can be signed; update calls are refused;
//! * the single exception is an explicitly authorized recovery call: one update call to
//!   Governance `manage_neuron` whose argument bytes equal a pre-approved payload exactly
//!   (see `with_authorized_manage_neuron`); every other update call is refused;
//! * `sign_arbitrary` / `sign_delegation` are unsupported (trait defaults);
//! * a hard cap on the number of signatures per process;
//! * every signature is verified locally against the Oracle public key before it is returned.

use crate::identity::{principal_from_sec1, sec1_to_spki_der};
use candid::Principal;
use ic_agent::{agent::EnvelopeContent, Agent, Identity, Signature};
use k256::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

/// Produces the raw 64-byte (r || s) ECDSA signature over a 32-byte digest.
pub trait DigestSigner: Send + Sync {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String>;
}

#[derive(candid::CandidType, Deserialize)]
struct SignatureReply {
    signature: Vec<u8>,
}

/// Backend that calls `signing.sign` as the local owner identity (an update call; costs cycles).
pub struct CanisterSigner {
    pub owner_agent: Agent,
    pub signing_canister: Principal,
    pub handle: tokio::runtime::Handle,
}

impl DigestSigner for CanisterSigner {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        let arg = candid::encode_one(digest.to_vec()).map_err(|e| e.to_string())?;
        // `Identity::sign` is synchronous; this requires a multi-thread tokio runtime.
        let bytes = tokio::task::block_in_place(|| {
            self.handle.block_on(
                self.owner_agent
                    .update(&self.signing_canister, "sign")
                    .with_arg(arg)
                    .call_and_wait(),
            )
        })
        .map_err(|e| format!("signing.sign call failed: {e}"))?;
        let reply: Result<SignatureReply, String> =
            candid::decode_one(&bytes).map_err(|e| format!("cannot decode sign reply: {e}"))?;
        reply
            .map(|r| r.signature)
            .map_err(|e| format!("signing.sign returned Err: {e}"))
    }
}

/// The only Governance query methods this tool will ever sign (both read-only).
pub const ALLOWED_QUERIES: [&str; 2] = ["list_neurons", "get_full_neuron"];

pub struct OracleIdentity {
    der: Vec<u8>,
    principal: Principal,
    verifying_key: VerifyingKey,
    governance: Principal,
    backend: Arc<dyn DigestSigner>,
    signatures_used: AtomicU32,
    max_signatures: u32,
    authorized_manage_neuron: Option<Vec<u8>>,
}

impl OracleIdentity {
    /// Permits exactly one `manage_neuron` payload (byte-for-byte) to be signed as an update call.
    pub fn with_authorized_manage_neuron(mut self, arg: Vec<u8>) -> Self {
        self.authorized_manage_neuron = Some(arg);
        self
    }

    /// Allows one exact StartDissolving request. The caller constructs this from a fresh
    /// controller-verified preflight; the wire bytes remain pinned for this identity.
    pub fn with_authorized_start_dissolving(self, arg: Vec<u8>) -> Self {
        if !crate::dissolve::is_start_payload(&arg) {
            return self;
        }
        self.with_authorized_manage_neuron(arg)
    }

    pub fn new(
        sec1: &[u8],
        governance: Principal,
        backend: Arc<dyn DigestSigner>,
        max_signatures: u32,
    ) -> Result<Self, String> {
        let der = sec1_to_spki_der(sec1)?;
        let principal = principal_from_sec1(sec1)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(sec1).map_err(|e| e.to_string())?;
        Ok(Self {
            der,
            principal,
            verifying_key,
            governance,
            backend,
            signatures_used: AtomicU32::new(0),
            max_signatures,
            authorized_manage_neuron: None,
        })
    }

    pub fn signatures_used(&self) -> u32 {
        self.signatures_used.load(Ordering::SeqCst)
    }

    fn check_policy(&self, content: &EnvelopeContent) -> Result<(), String> {
        match content {
            EnvelopeContent::Query {
                sender,
                canister_id,
                method_name,
                ..
            } => {
                if *sender != self.principal {
                    return Err("refusing to sign: sender is not the Oracle principal".into());
                }
                if *canister_id != self.governance
                    || !ALLOWED_QUERIES.contains(&method_name.as_str())
                {
                    return Err(format!(
                        "refusing to sign query {canister_id}.{method_name}: only Governance {ALLOWED_QUERIES:?} are allowed"
                    ));
                }
                Ok(())
            }
            EnvelopeContent::ReadState { sender, .. } => {
                if *sender != self.principal {
                    return Err("refusing to sign: sender is not the Oracle principal".into());
                }
                Ok(())
            }
            EnvelopeContent::Call {
                sender,
                canister_id,
                method_name,
                arg,
                ..
            } => {
                let Some(approved) = &self.authorized_manage_neuron else {
                    return Err("refusing to sign an update call: this tool is read-only".into());
                };
                if *sender != self.principal
                    || *canister_id != self.governance
                    || method_name != "manage_neuron"
                    || arg != approved
                {
                    return Err("refusing to sign an update call that is not the single approved manage_neuron payload".into());
                }
                Ok(())
            }
        }
    }

    /// Signs the exact bytes `ic-agent` signs for a request: `"\x0Aic-request" || request_id`.
    fn sign_signable(&self, signable: &[u8]) -> Result<Vec<u8>, String> {
        let used = self.signatures_used.fetch_add(1, Ordering::SeqCst);
        if used >= self.max_signatures {
            return Err(format!("signature cap reached ({})", self.max_signatures));
        }
        let digest: [u8; 32] = Sha256::digest(signable).into();
        let raw = self.backend.sign_digest(&digest)?;
        let sig = EcdsaSignature::from_slice(&raw)
            .map_err(|e| format!("malformed signature from signing canister: {e}"))?;
        // Low-S is accepted by every verifier; high-S is mathematically equivalent.
        let sig = sig.normalize_s().unwrap_or(sig);
        self.verifying_key.verify(signable, &sig).map_err(|_| {
            "signature does not verify against the Oracle public key; not sending".to_string()
        })?;
        Ok(sig.to_bytes().to_vec())
    }
}

impl Identity for OracleIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.principal)
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.der.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.check_policy(content)?;
        let signature = self.sign_signable(&content.to_request_id().signable())?;
        Ok(Signature {
            public_key: Some(self.der.clone()),
            signature: Some(signature),
            delegations: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use k256::SecretKey;

    const SECRET: [u8; 32] = [7u8; 32];

    fn governance() -> Principal {
        Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()
    }

    struct LocalBackend(SigningKey);
    impl DigestSigner for LocalBackend {
        fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
            let s: EcdsaSignature = self.0.sign_prehash(digest).map_err(|e| e.to_string())?;
            Ok(s.to_bytes().to_vec())
        }
    }

    // Returns the high-S twin of a valid signature.
    struct HighSBackend(SigningKey);
    impl DigestSigner for HighSBackend {
        fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
            let s: EcdsaSignature = self.0.sign_prehash(digest).map_err(|e| e.to_string())?;
            let (r, s) = s.split_scalars();
            let high = EcdsaSignature::from_scalars(r, -*s).map_err(|e| e.to_string())?;
            Ok(high.to_bytes().to_vec())
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SECRET.into()).unwrap()
    }

    fn sec1() -> Vec<u8> {
        signing_key()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn identity_with(backend: Arc<dyn DigestSigner>, max: u32) -> OracleIdentity {
        OracleIdentity::new(&sec1(), governance(), backend, max).unwrap()
    }

    fn identity() -> OracleIdentity {
        identity_with(Arc::new(LocalBackend(signing_key())), 3)
    }

    fn query(sender: Principal, canister: Principal, method: &str) -> EnvelopeContent {
        EnvelopeContent::Query {
            ingress_expiry: 1_700_000_000_000_000_000,
            sender,
            canister_id: canister,
            method_name: method.to_string(),
            arg: b"DIDL\0\0".to_vec(),
            nonce: None,
            sender_info: None,
        }
    }

    #[test]
    fn sender_and_public_key_match_stage_a_derivation() {
        let id = identity();
        let der = sec1_to_spki_der(&sec1()).unwrap();
        assert_eq!(id.public_key().unwrap(), der);
        assert_eq!(id.sender().unwrap(), Principal::self_authenticating(&der));
        assert_eq!(id.sender().unwrap(), principal_from_sec1(&sec1()).unwrap());
    }

    #[test]
    fn signature_is_identical_to_ic_agent_reference_identity() {
        // Secp256k1Identity signs SHA-256(signable) with deterministic RFC 6979; our flow
        // (digest -> prehash signing, like the canister) must produce the very same bytes.
        let reference = ic_agent::identity::Secp256k1Identity::from_private_key(
            SecretKey::from_bytes(&SECRET.into()).unwrap(),
        );
        let id = identity();
        assert_eq!(reference.sender().unwrap(), id.sender().unwrap());
        let content = query(id.sender().unwrap(), governance(), "list_neurons");
        let ours = id.sign(&content).unwrap();
        let theirs = reference.sign(&content).unwrap();
        assert_eq!(ours.signature, theirs.signature);
        assert_eq!(ours.public_key, theirs.public_key);
        assert!(ours.delegations.is_none());
        assert_eq!(ours.signature.unwrap().len(), 64);
    }

    #[test]
    fn signed_bytes_are_domain_separator_plus_request_id() {
        let id = identity();
        let content = query(id.sender().unwrap(), governance(), "list_neurons");
        let signable = content.to_request_id().signable();
        assert_eq!(signable.len(), 43);
        assert_eq!(&signable[..11], b"\x0Aic-request");
        let sig = id.sign(&content).unwrap().signature.unwrap();
        let sig = EcdsaSignature::from_slice(&sig).unwrap();
        signing_key()
            .verifying_key()
            .verify(&signable, &sig)
            .unwrap();
    }

    #[test]
    fn high_s_signatures_are_normalized() {
        let id = identity_with(Arc::new(HighSBackend(signing_key())), 3);
        let content = query(id.sender().unwrap(), governance(), "list_neurons");
        let sig = id.sign(&content).unwrap().signature.unwrap();
        let sig = EcdsaSignature::from_slice(&sig).unwrap();
        assert!(
            sig.normalize_s().is_none(),
            "returned signature must be low-S"
        );
    }

    #[test]
    fn signature_from_wrong_key_is_rejected() {
        let other = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let id = identity_with(Arc::new(LocalBackend(other)), 3);
        let content = query(id.sender().unwrap(), governance(), "list_neurons");
        assert!(id.sign(&content).unwrap_err().contains("does not verify"));
    }

    fn call(sender: Principal, canister: Principal, method: &str, arg: &[u8]) -> EnvelopeContent {
        EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 1,
            sender,
            canister_id: canister,
            method_name: method.into(),
            arg: arg.to_vec(),
            sender_info: None,
        }
    }

    #[test]
    fn authorized_manage_neuron_is_exact() {
        let plain = identity();
        let me = plain.sender().unwrap();
        assert!(plain
            .sign(&call(me, governance(), "manage_neuron", b"x"))
            .is_err());

        let id = identity_with(Arc::new(LocalBackend(signing_key())), 3)
            .with_authorized_manage_neuron(b"x".to_vec());
        assert!(id
            .sign(&call(me, governance(), "manage_neuron", b"y"))
            .is_err());
        assert!(id
            .sign(&call(me, governance(), "manage_neuron", b""))
            .is_err());
        assert!(id
            .sign(&call(me, governance(), "list_neurons", b"x"))
            .is_err());
        assert!(id
            .sign(&call(me, Principal::anonymous(), "manage_neuron", b"x"))
            .is_err());
        assert!(id
            .sign(&call(
                Principal::anonymous(),
                governance(),
                "manage_neuron",
                b"x"
            ))
            .is_err());
        assert_eq!(id.signatures_used(), 0);
        assert!(id
            .sign(&call(me, governance(), "manage_neuron", b"x"))
            .is_ok());
        assert_eq!(id.signatures_used(), 1);
    }

    #[test]
    fn start_dissolving_capability_rejects_other_payloads_and_methods() {
        let me = identity().sender().unwrap();
        let valid = crate::dissolve::encode_start_dissolving(17).unwrap();
        let invalid = b"not a start request".to_vec();
        let restricted = identity_with(Arc::new(LocalBackend(signing_key())), 3)
            .with_authorized_start_dissolving(invalid.clone());
        assert!(restricted
            .sign(&call(me, governance(), "manage_neuron", &invalid))
            .is_err());
        let restricted = identity_with(Arc::new(LocalBackend(signing_key())), 3)
            .with_authorized_start_dissolving(valid.clone());
        assert!(restricted
            .sign(&call(me, governance(), "manage_neuron", b"other"))
            .is_err());
        assert!(restricted
            .sign(&call(me, governance(), "manage_neuron", &valid))
            .is_ok());
        assert!(restricted
            .sign(&call(me, Principal::anonymous(), "manage_neuron", &valid))
            .is_err());
    }

    #[test]
    fn refuses_everything_but_list_neurons_and_read_state() {
        let id = identity();
        let me = id.sender().unwrap();
        assert!(id
            .sign(&query(me, governance(), "get_neuron_info"))
            .is_err());
        assert!(id.sign(&query(me, governance(), "get_full_neuron")).is_ok());
        let call = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 1,
            sender: me,
            canister_id: governance(),
            method_name: "manage_neuron".into(),
            arg: vec![],
            sender_info: None,
        };
        assert!(id.sign(&call).unwrap_err().contains("update call"));
        assert!(id.sign(&query(me, governance(), "manage_neuron")).is_err());
        assert!(id
            .sign(&query(me, Principal::anonymous(), "list_neurons"))
            .is_err());
        assert!(id
            .sign(&query(Principal::anonymous(), governance(), "list_neurons"))
            .is_err());
        let rs = EnvelopeContent::ReadState {
            ingress_expiry: 1,
            sender: me,
            paths: vec![],
        };
        assert!(id.sign(&rs).is_ok());
        // Refused requests never reach the backend, so they never consume the cap.
        assert_eq!(id.signatures_used(), 2);
        assert!(id.sign_arbitrary(b"anything").is_err());
        assert!(id
            .sign_delegation(&ic_agent::identity::Delegation {
                pubkey: vec![],
                expiration: 0,
                targets: None,
                permissions: None,
            })
            .is_err());
    }

    #[test]
    fn signature_cap_is_enforced() {
        let id = identity_with(Arc::new(LocalBackend(signing_key())), 2);
        let content = query(id.sender().unwrap(), governance(), "list_neurons");
        assert!(id.sign(&content).is_ok());
        assert!(id.sign(&content).is_ok());
        assert!(id.sign(&content).unwrap_err().contains("cap"));
        assert_eq!(id.signatures_used(), 3);
    }
}
