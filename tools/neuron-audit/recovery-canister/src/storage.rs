//! Durable record format: `MAGIC (8) | payload length u64 LE (8) | candid(State)`, stored at
//! offset 0 of stable memory. A write happens inside one message, so it is atomic.

use crate::types::State;

pub const MAGIC: &[u8; 8] = b"STICPREC";
pub const HEADER_LEN: usize = 16;
/// Stable memory is grown to this many 64 KiB pages at install, so later writes never need to
/// grow it. The state is bounded by `MAX_OPERATIONS` and is a few kilobytes at most.
pub const RESERVED_PAGES: u64 = 2;
pub const PAGE_BYTES: u64 = 65_536;

pub fn encode(state: &State) -> Result<Vec<u8>, String> {
    let payload = candid::encode_one(state).map_err(|e| format!("cannot encode state: {e}"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Length of the payload announced by a header.
pub fn payload_len(header: &[u8; HEADER_LEN]) -> Result<usize, String> {
    if &header[..8] != MAGIC {
        return Err("stable memory does not contain a recovery state record".to_string());
    }
    let mut len = [0u8; 8];
    len.copy_from_slice(&header[8..]);
    usize::try_from(u64::from_le_bytes(len)).map_err(|_| "state length overflow".to_string())
}

pub fn decode_payload(payload: &[u8]) -> Result<State, String> {
    let state: State =
        candid::decode_one(payload).map_err(|e| format!("cannot decode state: {e}"))?;
    if state.version != State::VERSION {
        return Err(format!("unsupported state version {}", state.version));
    }
    Ok(state)
}

pub fn decode(bytes: &[u8]) -> Result<State, String> {
    let header: [u8; HEADER_LEN] = bytes
        .get(..HEADER_LEN)
        .and_then(|h| h.try_into().ok())
        .ok_or_else(|| "record too short".to_string())?;
    let len = payload_len(&header)?;
    let end = HEADER_LEN
        .checked_add(len)
        .ok_or_else(|| "state length overflow".to_string())?;
    let payload = bytes
        .get(HEADER_LEN..end)
        .ok_or_else(|| "record truncated".to_string())?;
    decode_payload(payload)
}
