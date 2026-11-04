//! IC entry points: thin wrappers around [`Engine`] plus the real ledger and stable storage.

use crate::engine::{Clock, Engine, Ledger, Store};
use crate::storage;
use crate::types::*;
use candid::{CandidType, Nat, Principal};
use ic_cdk::call::Call;
use ic_cdk::stable::{stable_grow, stable_read, stable_size, stable_write};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use std::cell::RefCell;
use std::rc::Rc;

struct IcLedger(Principal);

impl IcLedger {
    async fn call<A: CandidType, R: CandidType + for<'de> candid::Deserialize<'de>>(
        &self,
        method: &str,
        arg: A,
    ) -> Result<R, String> {
        // Unbounded wait: a response always arrives, so there is no timeout-induced ambiguity.
        let response = Call::unbounded_wait(self.0, method)
            .with_arg(arg)
            .await
            .map_err(|e| format!("{method} call failed: {e}"))?;
        response
            .candid::<R>()
            .map_err(|e| format!("{method} reply undecodable: {e}"))
    }
}

fn nat_to_u64(n: &Nat) -> Result<u64, String> {
    u64::try_from(&n.0).map_err(|_| format!("value {n} does not fit in u64"))
}

impl Ledger for IcLedger {
    async fn fee(&self) -> Result<u64, String> {
        let fee: Nat = self.call("icrc1_fee", ()).await?;
        nat_to_u64(&fee)
    }

    async fn balance_of(&self, account: Account) -> Result<u64, String> {
        let balance: Nat = self.call("icrc1_balance_of", account).await?;
        nat_to_u64(&balance)
    }

    async fn transfer(&self, args: TransferArg) -> Result<Result<Nat, TransferError>, String> {
        self.call("icrc1_transfer", args).await
    }
}

struct StableStore;

impl Store for StableStore {
    fn save(&self, state: &State) -> Result<(), String> {
        let bytes = storage::encode(state)?;
        let needed = (bytes.len() as u64).div_ceil(storage::PAGE_BYTES);
        let have = stable_size();
        if needed > have {
            stable_grow(needed - have).map_err(|e| format!("cannot grow stable memory: {e:?}"))?;
        }
        stable_write(0, &bytes);
        Ok(())
    }
}

fn load_state() -> Result<Option<State>, String> {
    if stable_size() == 0 {
        return Ok(None);
    }
    let mut header = [0u8; storage::HEADER_LEN];
    stable_read(0, &mut header);
    let len = storage::payload_len(&header)?;
    if (len as u64).saturating_add(storage::HEADER_LEN as u64) > stable_size() * storage::PAGE_BYTES
    {
        return Err("stored state length exceeds stable memory".to_string());
    }
    let mut payload = vec![0u8; len];
    stable_read(storage::HEADER_LEN as u64, &mut payload);
    storage::decode_payload(&payload).map(Some)
}

struct IcClock;

impl Clock for IcClock {
    fn now_nanos(&self) -> u64 {
        ic_cdk::api::time()
    }
}

type IcEngine = Engine<IcLedger, StableStore, IcClock>;

thread_local! {
    static ENGINE: RefCell<Option<Rc<IcEngine>>> = const { RefCell::new(None) };
}

/// Builds the engine from stable memory. Traps (rolling back install/upgrade) on any problem:
/// never starts from a blank state over an unreadable record.
fn init_engine() {
    let config = Config::mainnet().unwrap_or_else(|e| ic_cdk::trap(e));
    let self_id = ic_cdk::api::canister_self();
    if self_id != config.source_canister {
        ic_cdk::trap(format!(
            "this module may only be installed in {SOURCE_CANISTER}, not {self_id}"
        ));
    }
    let state = match load_state() {
        Ok(Some(s)) => s,
        Ok(None) => {
            if let Err(e) = stable_grow(storage::RESERVED_PAGES) {
                ic_cdk::trap(format!("cannot reserve stable memory: {e:?}"));
            }
            let s = State::new();
            if let Err(e) = StableStore.save(&s) {
                ic_cdk::trap(e);
            }
            s
        }
        Err(e) => ic_cdk::trap(format!("refusing to start: {e}")),
    };
    let ledger = IcLedger(config.ledger);
    let engine = Engine::new(config, self_id, ledger, StableStore, IcClock, state);
    ENGINE.with(|e| *e.borrow_mut() = Some(Rc::new(engine)));
}

fn engine() -> Rc<IcEngine> {
    if ENGINE.with(|e| e.borrow().is_none()) {
        init_engine();
    }
    ENGINE
        .with(|e| e.borrow().clone())
        .unwrap_or_else(|| ic_cdk::trap("engine not initialized"))
}

#[ic_cdk::init]
fn init() {
    init_engine();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    init_engine();
}

/// Sends `amount_e8s` from this canister's default account to the fixed recipient.
#[ic_cdk::update]
async fn transfer(req: TransferRequest) -> Result<TransferOk, RecoveryError> {
    engine().transfer(ic_cdk::api::msg_caller(), req).await
}

/// Re-sends the in-doubt operation with identical arguments (idempotent through the ledger's
/// deduplication).
#[ic_cdk::update]
async fn retry_pending(operation_id: u64) -> Result<TransferOk, RecoveryError> {
    engine()
        .retry_pending(ic_cdk::api::msg_caller(), operation_id)
        .await
}

/// Marks an in-doubt operation as not executed; only after the ledger dedup window has passed.
#[ic_cdk::update]
fn abandon_pending(operation_id: u64) -> Result<(), RecoveryError> {
    engine().abandon_pending(ic_cdk::api::msg_caller(), operation_id)
}

#[ic_cdk::query]
fn get_state() -> State {
    engine().state()
}

#[ic_cdk::query]
fn get_config() -> ConfigView {
    let e = engine();
    let c = e.config();
    ConfigView {
        source_canister: c.source_canister,
        authorized_caller: c.authorized_caller,
        destination: c.destination,
        ledger: c.ledger,
        fee_e8s: c.fee_e8s,
        max_operations: MAX_OPERATIONS as u64,
    }
}
