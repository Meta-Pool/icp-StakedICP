//! Loading of the local owner identity (the principal allowed to call `signing.sign`).
//! The key material is never printed, logged or written anywhere.

use anyhow::{anyhow, bail, Context, Result};
use ic_agent::{
    identity::{BasicIdentity, Secp256k1Identity},
    Identity,
};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Reads a PEM from a file, or from stdin when `path` is `-`.
pub fn load_owner_identity(path: &Path) -> Result<Box<dyn Identity>> {
    let mut pem = Zeroizing::new(String::new());
    if path == Path::new("-") {
        std::io::stdin()
            .read_to_string(&mut pem)
            .context("cannot read owner PEM from stdin")?;
    } else {
        *pem = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read owner PEM file {}", path.display()))?;
    }
    if pem.trim().is_empty() {
        bail!("owner PEM is empty");
    }
    // dfx identities are secp256k1 (current default) or ed25519 (older default).
    if let Ok(id) = Secp256k1Identity::from_pem(pem.as_bytes()) {
        return Ok(Box::new(id));
    }
    BasicIdentity::from_pem(pem.as_bytes())
        .map(|id| Box::new(id) as Box<dyn Identity>)
        .map_err(|_| anyhow!("owner PEM is neither a valid secp256k1 nor ed25519 key"))
}
