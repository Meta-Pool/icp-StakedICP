//! Unit tests of the transfer engine against a mocked ledger that models the ICP ledger's
//! `icrc1_transfer` semantics (explicit fee, 24 h dedup window, duplicate detection before the
//! balance check).

use candid::{Nat, Principal};
use futures::channel::oneshot;
use futures::executor::block_on;
use futures::future::join;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use recovery_canister::engine::{Clock, Engine, Ledger, Store};
use recovery_canister::storage;
use recovery_canister::types::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

const HOUR: u64 = 3_600_000_000_000;
const START_BALANCE: u64 = 94_233_666_604;

fn p(n: u8) -> Principal {
    Principal::from_slice(&[n, 1, 2, 3])
}

fn cfg() -> Config {
    Config {
        source_canister: p(10),
        authorized_caller: p(1),
        destination: p(2),
        ledger: p(3),
        fee_e8s: LEDGER_FEE_E8S,
    }
}

/// What the mock ledger does with the next transfer call.
enum Script {
    /// Behave like the real ledger.
    Normal,
    /// Execute the transfer, then lose the reply (call failure).
    ExecuteThenLoseReply,
    /// Fail the call before the ledger sees it.
    CallFailsBeforeExecution,
    /// Answer with this error without executing.
    Refuse(TransferError),
}

#[derive(Default)]
struct LedgerState {
    fee: u64,
    fee_query_error: bool,
    balances: Vec<(Account, u64)>,
    seen: Vec<(Vec<u8>, u64)>,
    executed: Vec<TransferArg>,
    calls: Vec<TransferArg>,
    script: VecDeque<Script>,
    gate: Option<oneshot::Receiver<()>>,
    now: Rc<Cell<u64>>,
}

#[derive(Clone)]
struct MockLedger(Rc<RefCell<LedgerState>>);

fn key(a: &TransferArg) -> Vec<u8> {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        a.from_subaccount, a.to, a.amount, a.fee, a.memo, a.created_at_time
    )
    .into_bytes()
}

impl MockLedger {
    fn new(self_id: Principal, balance: u64, now: Rc<Cell<u64>>) -> Self {
        Self(Rc::new(RefCell::new(LedgerState {
            fee: LEDGER_FEE_E8S,
            balances: vec![(
                Account {
                    owner: self_id,
                    subaccount: None,
                },
                balance,
            )],
            now,
            ..Default::default()
        })))
    }
    fn push(&self, s: Script) {
        self.0.borrow_mut().script.push_back(s);
    }
    fn executed(&self) -> usize {
        self.0.borrow().executed.len()
    }
    fn calls(&self) -> Vec<TransferArg> {
        self.0.borrow().calls.clone()
    }
    fn balance(&self, a: &Account) -> u64 {
        self.0
            .borrow()
            .balances
            .iter()
            .find(|(x, _)| x == a)
            .map(|(_, b)| *b)
            .unwrap_or(0)
    }
    fn execute(&self, args: &TransferArg, from: Account) -> Result<Nat, TransferError> {
        let mut s = self.0.borrow_mut();
        let now = s.now.get();
        let created = args.created_at_time.unwrap_or(now);
        if created.saturating_add(24 * HOUR + 120_000_000_000) < now {
            return Err(TransferError::TooOld);
        }
        let k = key(args);
        if let Some((_, block)) = s.seen.iter().find(|(x, _)| *x == k) {
            return Err(TransferError::Duplicate {
                duplicate_of: Nat::from(*block),
            });
        }
        let fee = args.fee.clone().map(|f| u64::try_from(&f.0).unwrap_or(0));
        if fee != Some(s.fee) {
            return Err(TransferError::BadFee {
                expected_fee: Nat::from(s.fee),
            });
        }
        let amount = u64::try_from(&args.amount.0).unwrap_or(u64::MAX);
        let have = s
            .balances
            .iter()
            .find(|(x, _)| *x == from)
            .map(|(_, b)| *b)
            .unwrap_or(0);
        let need = amount + s.fee;
        if have < need {
            return Err(TransferError::InsufficientFunds {
                balance: Nat::from(have),
            });
        }
        for (a, b) in s.balances.iter_mut() {
            if *a == from {
                *b -= need;
            }
        }
        if let Some((_, b)) = s.balances.iter_mut().find(|(a, _)| *a == args.to) {
            *b += amount;
        } else {
            s.balances.push((args.to, amount));
        }
        let block = s.executed.len() as u64 + 100;
        s.seen.push((k, block));
        s.executed.push(args.clone());
        Ok(Nat::from(block))
    }
}

impl Ledger for MockLedger {
    async fn fee(&self) -> Result<u64, String> {
        let s = self.0.borrow();
        if s.fee_query_error {
            return Err("fee query failed".into());
        }
        Ok(s.fee)
    }
    async fn balance_of(&self, account: Account) -> Result<u64, String> {
        Ok(self.balance(&account))
    }
    async fn transfer(&self, args: TransferArg) -> Result<Result<Nat, TransferError>, String> {
        let gate = {
            let mut s = self.0.borrow_mut();
            s.calls.push(args.clone());
            s.gate.take()
        };
        if let Some(g) = gate {
            let _ = g.await;
        }
        let script = self
            .0
            .borrow_mut()
            .script
            .pop_front()
            .unwrap_or(Script::Normal);
        let from = self.0.borrow().balances[0].0;
        match script {
            Script::Normal => Ok(self.execute(&args, from)),
            Script::ExecuteThenLoseReply => {
                let _ = self.execute(&args, from);
                Err("reply lost".into())
            }
            Script::CallFailsBeforeExecution => Err("call rejected".into()),
            Script::Refuse(e) => Ok(Err(e)),
        }
    }
}

#[derive(Clone, Default)]
struct MemStore {
    saved: Rc<RefCell<Option<State>>>,
    fail: Rc<Cell<bool>>,
    saves: Rc<Cell<u32>>,
}

impl Store for MemStore {
    fn save(&self, state: &State) -> Result<(), String> {
        if self.fail.get() {
            return Err("disk full".into());
        }
        // Prove the real record format is used and round-trips.
        let bytes = storage::encode(state)?;
        *self.saved.borrow_mut() = Some(storage::decode(&bytes)?);
        self.saves.set(self.saves.get() + 1);
        Ok(())
    }
}

#[derive(Clone)]
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn now_nanos(&self) -> u64 {
        self.0.get()
    }
}

type TestEngine = Engine<MockLedger, MemStore, TestClock>;

struct Env {
    engine: Rc<TestEngine>,
    ledger: MockLedger,
    store: MemStore,
    now: Rc<Cell<u64>>,
}

impl Env {
    fn new(balance: u64) -> Self {
        Self::with_state(balance, State::new(), None)
    }
    fn with_state(
        balance: u64,
        state: State,
        reuse: Option<(MockLedger, MemStore, Rc<Cell<u64>>)>,
    ) -> Self {
        let (ledger, store, now) = reuse.unwrap_or_else(|| {
            let now = Rc::new(Cell::new(1_000 * HOUR));
            (
                MockLedger::new(p(10), balance, now.clone()),
                MemStore::default(),
                now,
            )
        });
        let engine = Rc::new(Engine::new(
            cfg(),
            p(10),
            ledger.clone(),
            store.clone(),
            TestClock(now.clone()),
            state,
        ));
        Self {
            engine,
            ledger,
            store,
            now,
        }
    }
    /// Simulates an upgrade/restart: a new engine loads the durable state.
    fn restart(&self) -> Env {
        let state = self.store.saved.borrow().clone().unwrap_or_default();
        Env::with_state(
            0,
            state,
            Some((self.ledger.clone(), self.store.clone(), self.now.clone())),
        )
    }
    fn src(&self) -> Account {
        self.engine.source_account()
    }
    fn dst(&self) -> Account {
        Account {
            owner: p(2),
            subaccount: None,
        }
    }
    fn transfer(&self, id: u64, amount: u64) -> Result<TransferOk, RecoveryError> {
        block_on(self.engine.transfer(p(1), req(id, amount)))
    }
    fn retry(&self, id: u64) -> Result<TransferOk, RecoveryError> {
        block_on(self.engine.retry_pending(p(1), id))
    }
}

fn req(id: u64, amount: u64) -> TransferRequest {
    TransferRequest {
        expected_operation_id: id,
        amount_e8s: amount,
        expected_fee_e8s: LEDGER_FEE_E8S,
        manifest_tag: vec![7; MANIFEST_TAG_LEN],
    }
}

// ---- 1. caller authorization ----

#[test]
fn rejects_unauthorized_callers_everywhere_without_touching_the_ledger() {
    let env = Env::new(START_BALANCE);
    for caller in [
        Principal::anonymous(),
        p(99),
        cfg().destination,
        cfg().source_canister,
    ] {
        assert_eq!(
            block_on(env.engine.transfer(caller, req(1, TEST_TRANSFER_E8S))),
            Err(RecoveryError::Unauthorized)
        );
        assert_eq!(
            block_on(env.engine.retry_pending(caller, 1)),
            Err(RecoveryError::Unauthorized)
        );
        assert_eq!(
            env.engine.abandon_pending(caller, 1),
            Err(RecoveryError::Unauthorized)
        );
    }
    assert!(env.ledger.calls().is_empty());
    assert_eq!(env.engine.state(), State::new());
    assert_eq!(env.store.saves.get(), 0);
}

#[test]
fn production_config_parses_and_is_fixed() {
    let c = Config::mainnet().unwrap();
    assert_eq!(c.source_canister.to_text(), "hnwvc-lyaaa-aaaal-aaf6q-cai");
    assert_eq!(c.authorized_caller.to_text(), AUTHORIZED_CALLER);
    assert_eq!(c.destination.to_text(), DESTINATION_PRINCIPAL);
    assert_eq!(c.ledger.to_text(), "ryjl3-tyaaa-aaaaa-aaaba-cai");
    assert_eq!(c.fee_e8s, 10_000);
    assert_eq!(TEST_TRANSFER_E8S, 10_000_000);
}

// ---- 2. destination ----

#[test]
fn every_ledger_call_goes_from_the_default_account_to_the_fixed_destination() {
    let env = Env::new(START_BALANCE);
    env.transfer(1, TEST_TRANSFER_E8S).unwrap();
    let calls = env.ledger.calls();
    assert_eq!(calls.len(), 1);
    let c = &calls[0];
    assert_eq!(c.from_subaccount, None);
    assert_eq!(
        c.to,
        Account {
            owner: p(2),
            subaccount: None
        }
    );
    assert_eq!(c.fee, Some(Nat::from(LEDGER_FEE_E8S)));
    assert_eq!(c.amount, Nat::from(TEST_TRANSFER_E8S));
    let memo = c.memo.clone().unwrap().0.to_vec();
    assert_eq!(memo.len(), 8 + MANIFEST_TAG_LEN);
    assert_eq!(&memo[..8], &1u64.to_be_bytes());
    assert_eq!(&memo[8..], &[7u8; MANIFEST_TAG_LEN]);
    assert!(c.created_at_time.is_some());
    assert_eq!(env.ledger.balance(&env.dst()), TEST_TRANSFER_E8S);
}

#[test]
fn rejects_malformed_requests_before_any_state_or_ledger_effect() {
    let env = Env::new(START_BALANCE);
    assert_eq!(env.transfer(1, 0), Err(RecoveryError::ZeroAmount));
    let mut r = req(1, 5);
    r.manifest_tag = vec![1; 15];
    assert_eq!(
        block_on(env.engine.transfer(p(1), r)),
        Err(RecoveryError::InvalidManifestTag)
    );
    let mut r = req(1, 5);
    r.expected_fee_e8s = 20_000;
    assert_eq!(
        block_on(env.engine.transfer(p(1), r)),
        Err(RecoveryError::UnexpectedFee {
            expected_e8s: 10_000,
            requested_e8s: 20_000
        })
    );
    assert!(env.ledger.calls().is_empty());
    assert_eq!(env.engine.state(), State::new());
}

// ---- 3. arithmetic and fees ----

#[test]
fn exact_e8s_accounting_for_test_then_final_transfer() {
    let env = Env::new(START_BALANCE);
    let ok = env.transfer(1, TEST_TRANSFER_E8S).unwrap();
    assert_eq!(
        ok,
        TransferOk {
            operation_id: 1,
            block_index: Nat::from(100u64),
            duplicate: false
        }
    );
    assert_eq!(
        env.ledger.balance(&env.src()),
        START_BALANCE - TEST_TRANSFER_E8S - LEDGER_FEE_E8S
    );
    // Sweep: everything but the fee.
    let remaining = env.ledger.balance(&env.src());
    let final_amount = remaining - LEDGER_FEE_E8S;
    assert_eq!(final_amount, 94_233_666_604 - 10_000_000 - 20_000);
    env.transfer(2, final_amount).unwrap();
    assert_eq!(env.ledger.balance(&env.src()), 0);
    assert_eq!(
        env.ledger.balance(&env.dst()),
        START_BALANCE - 2 * LEDGER_FEE_E8S
    );
    assert_eq!(env.ledger.executed(), 2);
}

#[test]
fn unexpected_live_ledger_fee_is_refused_and_nothing_is_recorded() {
    let env = Env::new(START_BALANCE);
    env.ledger.0.borrow_mut().fee = 20_000;
    assert_eq!(
        env.transfer(1, TEST_TRANSFER_E8S),
        Err(RecoveryError::UnexpectedLedgerFee {
            expected_e8s: 10_000,
            actual_e8s: 20_000
        })
    );
    assert!(env.ledger.calls().is_empty());
    assert_eq!(env.engine.state(), State::new());
}

#[test]
fn fee_query_failure_sends_nothing() {
    let env = Env::new(START_BALANCE);
    env.ledger.0.borrow_mut().fee_query_error = true;
    assert!(matches!(
        env.transfer(1, 5),
        Err(RecoveryError::LedgerQueryFailed { .. })
    ));
    assert!(env.ledger.calls().is_empty());
    assert_eq!(env.engine.state(), State::new());
}

// ---- 4. insufficient funds ----

#[test]
fn rejects_amounts_exceeding_balance_after_fee() {
    let env = Env::new(1_000_000);
    // balance == amount: fee does not fit.
    assert_eq!(
        env.transfer(1, 1_000_000),
        Err(RecoveryError::InsufficientFunds {
            balance_e8s: 1_000_000,
            required_e8s: 1_010_000
        })
    );
    assert_eq!(
        env.transfer(1, 1_000_000 - LEDGER_FEE_E8S + 1),
        Err(RecoveryError::InsufficientFunds {
            balance_e8s: 1_000_000,
            required_e8s: 1_000_001
        })
    );
    // u64 overflow of amount + fee is reported, not wrapped.
    assert!(matches!(
        env.transfer(1, u64::MAX),
        Err(RecoveryError::InsufficientFunds {
            required_e8s: u64::MAX,
            ..
        })
    ));
    assert!(env.ledger.calls().is_empty());
    assert_eq!(env.engine.state(), State::new());
    // Exactly balance - fee is accepted.
    env.transfer(1, 1_000_000 - LEDGER_FEE_E8S).unwrap();
    assert_eq!(env.ledger.balance(&env.src()), 0);
}

// ---- 5/9. duplicate invocation and no repeat after success ----

#[test]
fn replaying_an_approved_request_after_success_does_nothing() {
    let env = Env::new(START_BALANCE);
    env.transfer(1, TEST_TRANSFER_E8S).unwrap();
    for _ in 0..3 {
        assert_eq!(
            env.transfer(1, TEST_TRANSFER_E8S),
            Err(RecoveryError::OperationIdMismatch {
                expected_next: 2,
                requested: 1
            })
        );
    }
    assert_eq!(env.retry(1), Err(RecoveryError::NoPendingOperation));
    assert_eq!(
        env.engine.abandon_pending(p(1), 1),
        Err(RecoveryError::NoPendingOperation)
    );
    assert_eq!(env.ledger.executed(), 1);
    assert_eq!(env.ledger.calls().len(), 1);
}

#[test]
fn restart_after_success_keeps_the_history_and_blocks_replay() {
    let env = Env::new(START_BALANCE);
    env.transfer(1, TEST_TRANSFER_E8S).unwrap();
    let env2 = env.restart();
    assert_eq!(env2.engine.state().next_operation_id, 2);
    assert!(matches!(
        env2.engine.state().operations[0].status,
        Status::Completed { .. }
    ));
    assert_eq!(
        env2.transfer(1, TEST_TRANSFER_E8S),
        Err(RecoveryError::OperationIdMismatch {
            expected_next: 2,
            requested: 1
        })
    );
    assert_eq!(env.ledger.executed(), 1);
}

#[test]
fn operation_count_is_capped() {
    let env = Env::new(START_BALANCE);
    for i in 1..=MAX_OPERATIONS as u64 {
        env.transfer(i, 1_000).unwrap();
    }
    assert_eq!(
        env.transfer(MAX_OPERATIONS as u64 + 1, 1_000),
        Err(RecoveryError::OperationLimitReached)
    );
}

// ---- 6. concurrency ----

#[test]
fn overlapping_transfer_attempts_are_rejected_while_one_is_in_flight() {
    let env = Env::new(START_BALANCE);
    let (tx, rx) = oneshot::channel();
    env.ledger.0.borrow_mut().gate = Some(rx);
    let first = env.engine.transfer(p(1), req(1, TEST_TRANSFER_E8S));
    let engine = env.engine.clone();
    let ledger = env.ledger.clone();
    let second = async {
        // Runs while `first` is suspended inside the ledger call.
        let a = engine.transfer(p(1), req(1, TEST_TRANSFER_E8S)).await;
        let b = engine.transfer(p(1), req(2, TEST_TRANSFER_E8S)).await;
        let c = engine.retry_pending(p(1), 1).await;
        let d = engine.abandon_pending(p(1), 1);
        assert_eq!(
            ledger.calls().len(),
            1,
            "only the first attempt reached the ledger"
        );
        let _ = tx.send(());
        (a, b, c, d)
    };
    let (r1, (a, b, c, d)) = block_on(join(first, second));
    assert_eq!(a, Err(RecoveryError::Busy));
    assert_eq!(b, Err(RecoveryError::Busy));
    assert_eq!(c, Err(RecoveryError::Busy));
    assert_eq!(d, Err(RecoveryError::Busy));
    assert_eq!(r1.unwrap().operation_id, 1);
    assert_eq!(env.ledger.executed(), 1);
    assert!(!env.engine.is_busy());
    env.transfer(2, 1_000).unwrap();
}

#[test]
fn in_flight_operation_is_already_durable_and_visible_as_in_doubt() {
    let env = Env::new(START_BALANCE);
    let (tx, rx) = oneshot::channel();
    env.ledger.0.borrow_mut().gate = Some(rx);
    let store = env.store.clone();
    let first = env.engine.transfer(p(1), req(1, TEST_TRANSFER_E8S));
    let probe = async {
        let saved = store.saved.borrow().clone().unwrap();
        let _ = tx.send(());
        saved
    };
    let (_, saved) = block_on(join(first, probe));
    assert_eq!(saved.operations.len(), 1);
    assert!(matches!(saved.operations[0].status, Status::InDoubt { .. }));
    assert_eq!(saved.next_operation_id, 2);
}

// ---- 7. ledger errors ----

#[test]
fn definitive_first_attempt_refusal_marks_failed_and_allows_a_new_operation() {
    let env = Env::new(START_BALANCE);
    env.ledger
        .push(Script::Refuse(TransferError::TemporarilyUnavailable));
    assert_eq!(
        env.transfer(1, TEST_TRANSFER_E8S),
        Err(RecoveryError::Ledger {
            error: TransferError::TemporarilyUnavailable
        })
    );
    let st = env.engine.state();
    assert!(matches!(st.operations[0].status, Status::Failed { .. }));
    assert_eq!(env.ledger.executed(), 0);
    assert_eq!(env.retry(1), Err(RecoveryError::NoPendingOperation));
    // A fresh operation (new id, new created_at_time) is needed and allowed.
    env.transfer(2, TEST_TRANSFER_E8S).unwrap();
    assert_eq!(env.ledger.executed(), 1);
}

#[test]
fn each_definitive_ledger_error_is_reported_unchanged() {
    for e in [
        TransferError::BadFee {
            expected_fee: Nat::from(1u64),
        },
        TransferError::BadBurn {
            min_burn_amount: Nat::from(1u64),
        },
        TransferError::InsufficientFunds {
            balance: Nat::from(0u64),
        },
        TransferError::CreatedInFuture { ledger_time: 5 },
        TransferError::GenericError {
            error_code: Nat::from(9u64),
            message: "x".into(),
        },
    ] {
        let env = Env::new(START_BALANCE);
        env.ledger.push(Script::Refuse(e.clone()));
        assert_eq!(
            env.transfer(1, 5_000),
            Err(RecoveryError::Ledger { error: e })
        );
        assert!(matches!(
            env.engine.state().operations[0].status,
            Status::Failed { .. }
        ));
    }
}

#[test]
fn too_old_is_never_treated_as_proof_of_non_execution() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::Refuse(TransferError::TooOld));
    assert!(matches!(
        env.transfer(1, 5_000),
        Err(RecoveryError::Ambiguous { .. })
    ));
    assert!(matches!(
        env.engine.state().operations[0].status,
        Status::InDoubt { .. }
    ));
}

// ---- 8. ambiguous outcomes, retry and reconciliation ----

#[test]
fn lost_reply_then_retry_is_deduplicated_and_pays_exactly_once() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::ExecuteThenLoseReply);
    let err = env.transfer(1, TEST_TRANSFER_E8S).unwrap_err();
    assert!(matches!(
        err,
        RecoveryError::Ambiguous {
            operation_id: 1,
            ..
        }
    ));
    assert_eq!(env.ledger.executed(), 1, "the ledger did execute");
    // No new transfer can start while the outcome is unknown.
    assert_eq!(
        env.transfer(2, TEST_TRANSFER_E8S),
        Err(RecoveryError::UnresolvedOperation { operation_id: 1 })
    );
    assert_eq!(env.ledger.calls().len(), 1);
    // Retry re-sends identical arguments.
    env.now.set(env.now.get() + HOUR);
    let ok = env.retry(1).unwrap();
    assert!(ok.duplicate);
    assert_eq!(ok.block_index, Nat::from(100u64));
    assert_eq!(env.ledger.executed(), 1, "no second payment");
    let calls = env.ledger.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        key(&calls[0]),
        key(&calls[1]),
        "retry arguments are byte-identical"
    );
    let op = &env.engine.state().operations[0];
    assert_eq!(op.attempts, 2);
    assert_eq!(
        op.status,
        Status::Completed {
            block_index: Nat::from(100u64),
            duplicate: true
        }
    );
    assert_eq!(env.ledger.balance(&env.dst()), TEST_TRANSFER_E8S);
    // And a further retry/replay does nothing.
    assert_eq!(env.retry(1), Err(RecoveryError::NoPendingOperation));
    assert_eq!(env.ledger.calls().len(), 2);
}

#[test]
fn call_failure_before_execution_then_retry_executes_once() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::CallFailsBeforeExecution);
    assert!(matches!(
        env.transfer(1, TEST_TRANSFER_E8S),
        Err(RecoveryError::Ambiguous { .. })
    ));
    assert_eq!(env.ledger.executed(), 0);
    let ok = env.retry(1).unwrap();
    assert!(!ok.duplicate);
    assert_eq!(env.ledger.executed(), 1);
}

#[test]
fn repeated_ambiguity_keeps_the_operation_pending_and_never_pays_twice() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::ExecuteThenLoseReply);
    env.ledger.push(Script::CallFailsBeforeExecution);
    env.ledger.push(Script::CallFailsBeforeExecution);
    let _ = env.transfer(1, TEST_TRANSFER_E8S);
    assert!(matches!(env.retry(1), Err(RecoveryError::Ambiguous { .. })));
    assert!(matches!(env.retry(1), Err(RecoveryError::Ambiguous { .. })));
    assert_eq!(env.engine.state().operations[0].attempts, 3);
    assert!(env.retry(1).unwrap().duplicate);
    assert_eq!(env.ledger.executed(), 1);
}

#[test]
fn a_refusal_on_retry_is_not_trusted_as_proof() {
    // After a lost reply the ledger could answer a retry with a different error first (e.g. if the
    // fee changed). Only a first attempt's refusal marks the operation Failed.
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::ExecuteThenLoseReply);
    env.ledger.push(Script::Refuse(TransferError::BadFee {
        expected_fee: Nat::from(1u64),
    }));
    let _ = env.transfer(1, TEST_TRANSFER_E8S);
    assert!(matches!(env.retry(1), Err(RecoveryError::Ambiguous { .. })));
    assert!(matches!(
        env.engine.state().operations[0].status,
        Status::InDoubt { .. }
    ));
    assert_eq!(
        env.transfer(2, 5_000),
        Err(RecoveryError::UnresolvedOperation { operation_id: 1 })
    );
}

#[test]
fn restart_while_in_doubt_resumes_with_identical_arguments() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::ExecuteThenLoseReply);
    let _ = env.transfer(1, TEST_TRANSFER_E8S);
    let env2 = env.restart();
    assert_eq!(
        env2.transfer(2, 5_000),
        Err(RecoveryError::UnresolvedOperation { operation_id: 1 })
    );
    assert!(env2.retry(1).unwrap().duplicate);
    let calls = env.ledger.calls();
    assert_eq!(key(&calls[0]), key(&calls[1]));
    assert_eq!(env.ledger.executed(), 1);
}

#[test]
fn retry_is_refused_outside_the_safe_window_and_for_the_wrong_operation() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::CallFailsBeforeExecution);
    let _ = env.transfer(1, TEST_TRANSFER_E8S);
    assert_eq!(
        env.retry(2),
        Err(RecoveryError::OperationNotPending { operation_id: 2 })
    );
    env.now.set(env.now.get() + RETRY_WINDOW_NANOS + 1);
    assert!(matches!(
        env.retry(1),
        Err(RecoveryError::RetryWindowExpired {
            operation_id: 1,
            ..
        })
    ));
    assert_eq!(
        env.ledger.calls().len(),
        1,
        "no call was made outside the window"
    );
}

#[test]
fn abandon_is_only_possible_after_the_ledger_window_and_unblocks_new_operations() {
    let env = Env::new(START_BALANCE);
    env.ledger.push(Script::CallFailsBeforeExecution);
    let _ = env.transfer(1, TEST_TRANSFER_E8S);
    assert!(matches!(
        env.engine.abandon_pending(p(1), 1),
        Err(RecoveryError::AbandonTooEarly {
            operation_id: 1,
            ..
        })
    ));
    assert_eq!(
        env.engine.abandon_pending(p(1), 2),
        Err(RecoveryError::OperationNotPending { operation_id: 2 })
    );
    env.now.set(env.now.get() + ABANDON_AFTER_NANOS);
    // The ledger now rejects a replay of the old arguments.
    assert!(matches!(
        env.retry(1),
        Err(RecoveryError::RetryWindowExpired { .. })
    ));
    env.engine.abandon_pending(p(1), 1).unwrap();
    assert_eq!(env.engine.state().operations[0].status, Status::Abandoned);
    env.transfer(2, TEST_TRANSFER_E8S).unwrap();
}

// ---- durable state failures ----

#[test]
fn storage_failure_before_the_call_sends_nothing_and_leaves_no_trace() {
    let env = Env::new(START_BALANCE);
    env.store.fail.set(true);
    assert!(matches!(
        env.transfer(1, 5_000),
        Err(RecoveryError::StorageError { .. })
    ));
    assert!(env.ledger.calls().is_empty());
    assert_eq!(env.engine.state(), State::new());
    env.store.fail.set(false);
    env.transfer(1, 5_000).unwrap();
}

#[test]
fn storage_failure_after_the_call_still_returns_the_result_and_blocks_further_sends() {
    let env = Env::new(START_BALANCE);
    let (tx, rx) = oneshot::channel();
    env.ledger.0.borrow_mut().gate = Some(rx);
    let store = env.store.clone();
    let first = env.engine.transfer(p(1), req(1, 5_000));
    let sabotage = async {
        store.fail.set(true);
        let _ = tx.send(());
    };
    let (r, _) = block_on(join(first, sabotage));
    assert!(
        r.is_ok(),
        "the ledger result is reported even if it could not be persisted"
    );
    // Durable copy still says InDoubt (safe); in-memory says Completed.
    assert!(matches!(
        env.store.saved.borrow().as_ref().unwrap().operations[0].status,
        Status::InDoubt { .. }
    ));
    // Next mutating call must flush first and cannot proceed while storage is failing.
    assert!(matches!(
        env.transfer(2, 5_000),
        Err(RecoveryError::StorageError { .. })
    ));
    assert_eq!(env.ledger.executed(), 1);
    env.store.fail.set(false);
    env.transfer(2, 5_000).unwrap();
    assert!(matches!(
        env.store.saved.borrow().as_ref().unwrap().operations[0].status,
        Status::Completed { .. }
    ));
}

// ---- stable record format ----

#[test]
fn state_record_round_trips_and_stays_far_below_the_reserved_memory() {
    let mut st = State::new();
    for i in 1..=MAX_OPERATIONS as u64 {
        st.operations.push(Operation {
            id: i,
            amount_e8s: u64::MAX,
            fee_e8s: LEDGER_FEE_E8S,
            created_at_time_nanos: u64::MAX,
            memo: vec![255; 24],
            attempts: u32::MAX,
            status: Status::InDoubt {
                last_error: "e".repeat(400),
            },
        });
    }
    st.next_operation_id = 9;
    let bytes = storage::encode(&st).unwrap();
    assert!((bytes.len() as u64) < storage::PAGE_BYTES);
    assert_eq!(storage::decode(&bytes).unwrap(), st);
}

#[test]
fn corrupt_or_foreign_records_are_rejected() {
    let good = storage::encode(&State::new()).unwrap();
    assert!(storage::decode(&good[..10]).is_err());
    assert!(storage::decode(&good[..good.len() - 1]).is_err());
    let mut bad = good.clone();
    bad[0] ^= 1;
    assert!(storage::decode(&bad).is_err());
    let mut other = State::new();
    other.version = 99;
    assert!(storage::decode(&storage::encode(&other).unwrap()).is_err());
}

// ---- interface file ----

#[test]
fn candid_interface_matches_the_rust_types() {
    use candid::{IDLArgs, TypeEnv};
    use candid_parser::{parse_idl_args, IDLProg};
    let src = include_str!("../recovery.did");
    let prog: IDLProg = src.parse().unwrap();
    let mut env = TypeEnv::new();
    let actor = candid_parser::check_prog(&mut env, &prog).unwrap().unwrap();
    for m in [
        "transfer",
        "retry_pending",
        "abandon_pending",
        "get_state",
        "get_config",
    ] {
        assert!(env.get_method(&actor, m).is_ok(), "missing {m}");
    }
    // The interface has exactly these methods: no generic or recipient-taking endpoint.
    let svc = env.as_service(&actor).unwrap();
    assert_eq!(svc.len(), 5);

    let ty = env.get_method(&actor, "transfer").unwrap().args[0].clone();
    let bytes = candid::encode_one(req(1, 5)).unwrap();
    let decoded = IDLArgs::from_bytes_with_types(&bytes, &env, &[ty]).unwrap();
    assert!(decoded.to_string().contains("amount_e8s = 5"));
    // Responses (including every error variant) decode with the declared types.
    let ret = env.get_method(&actor, "transfer").unwrap().rets[0].clone();
    for r in [
        Err(RecoveryError::Ledger {
            error: TransferError::Duplicate {
                duplicate_of: Nat::from(1u64),
            },
        }),
        Err(RecoveryError::Busy),
        Ok(TransferOk {
            operation_id: 1,
            block_index: Nat::from(3u64),
            duplicate: false,
        }),
    ] {
        let bytes = candid::encode_one(r).unwrap();
        IDLArgs::from_bytes_with_types(&bytes, &env, std::slice::from_ref(&ret)).unwrap();
    }
    let _ = parse_idl_args("()").unwrap();
}
