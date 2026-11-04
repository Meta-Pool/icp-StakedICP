//! Derivation of the Oracle's self-authenticating principal from the signing
//! canister's ECDSA public key. Mirrors `cmd/oracle/src/identity/canister_identity.rs`.

use candid::CandidType;
use candid::Principal;
use k256::{pkcs8::EncodePublicKey, PublicKey};
use serde::Deserialize;

/// Historical Oracle ECDSA principal, to be verified (not assumed).
pub const HISTORICAL_ORACLE_PRINCIPAL: &str =
    "xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe";

#[derive(CandidType, Deserialize, Debug)]
pub struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

/// Decodes the reply of `public_key : () -> (variant { Ok: record { public_key: blob }; Err: text })`.
pub fn decode_public_key_reply(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let reply: Result<PublicKeyReply, String> =
        candid::decode_one(bytes).map_err(|e| format!("candid decode failed: {e}"))?;
    reply
        .map(|r| r.public_key)
        .map_err(|e| format!("signing canister returned Err: {e}"))
}

/// Validates a compressed SEC1 secp256k1 key and returns its SPKI DER encoding
/// (uncompressed point inside SPKI, as produced by the original Oracle).
pub fn sec1_to_spki_der(sec1: &[u8]) -> Result<Vec<u8>, String> {
    if sec1.len() != 33 {
        return Err(format!(
            "malformed public_key, len: {}, expected 33",
            sec1.len()
        ));
    }
    if sec1[0] != 0x02 && sec1[0] != 0x03 {
        return Err(format!(
            "not a compressed SEC1 key, prefix 0x{:02x}",
            sec1[0]
        ));
    }
    let key =
        PublicKey::from_sec1_bytes(sec1).map_err(|e| format!("invalid secp256k1 key: {e}"))?;
    let der = key
        .to_public_key_der()
        .map_err(|e| format!("DER encoding failed: {e}"))?;
    Ok(der.as_bytes().to_vec())
}

pub fn principal_from_sec1(sec1: &[u8]) -> Result<Principal, String> {
    Ok(Principal::self_authenticating(sec1_to_spki_der(sec1)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use sha2::{Digest, Sha224};

    const SPKI_SECP256K1_PREFIX: [u8; 23] = [
        0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
    ];

    // Fixed, worthless test scalar; only its public key is used.
    fn test_key() -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        (
            vk.to_encoded_point(true).as_bytes().to_vec(),
            vk.to_encoded_point(false).as_bytes().to_vec(),
        )
    }

    #[test]
    fn der_is_spki_with_uncompressed_point() {
        let (compressed, uncompressed) = test_key();
        let der = sec1_to_spki_der(&compressed).unwrap();
        assert_eq!(der.len(), 88);
        assert_eq!(&der[..23], &SPKI_SECP256K1_PREFIX);
        assert_eq!(&der[23..], uncompressed.as_slice());
    }

    #[test]
    fn principal_is_sha224_of_der_plus_tag() {
        let (compressed, _) = test_key();
        let der = sec1_to_spki_der(&compressed).unwrap();
        let mut expected = Sha224::digest(&der).to_vec();
        expected.push(0x02);
        let p = principal_from_sec1(&compressed).unwrap();
        assert_eq!(p.as_slice(), expected.as_slice());
        assert_eq!(p.as_slice().len(), 29);
        assert_eq!(Principal::from_text(p.to_text()).unwrap(), p);
    }

    #[test]
    fn rejects_bad_keys() {
        let (compressed, uncompressed) = test_key();
        assert!(sec1_to_spki_der(&compressed[..32]).is_err());
        assert!(sec1_to_spki_der(&uncompressed).is_err());
        let mut bad_prefix = compressed.clone();
        bad_prefix[0] = 0x04;
        assert!(sec1_to_spki_der(&bad_prefix).is_err());
        // x = 0 is not on the curve
        let mut off_curve = vec![0x02];
        off_curve.extend_from_slice(&[0u8; 32]);
        assert!(sec1_to_spki_der(&off_curve).is_err());
    }

    #[test]
    fn historical_principal_constant_parses() {
        assert!(Principal::from_text(HISTORICAL_ORACLE_PRINCIPAL).is_ok());
    }

    #[test]
    fn decodes_ok_and_err_variants() {
        let (compressed, _) = test_key();
        let ok: Result<PublicKeyReply, String> = Ok(PublicKeyReply {
            public_key: compressed.clone(),
        });
        let bytes = candid::encode_one(&ok).unwrap();
        assert_eq!(decode_public_key_reply(&bytes).unwrap(), compressed);

        let err: Result<PublicKeyReply, String> = Err("boom".into());
        let bytes = candid::encode_one(&err).unwrap();
        assert!(decode_public_key_reply(&bytes)
            .unwrap_err()
            .contains("boom"));
    }
}
