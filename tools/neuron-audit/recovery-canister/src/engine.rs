//! Transfer logic, independent of the IC runtime so it can be tested against a mocked ledger.
//!
//! Safety rules implemented here:
//! * every mutating call needs the authorized caller;
//! * one call at a time (`busy` is held across every `await`);
//! * the operation, with the exact `created_at_time` and `memo`, is written durably BEFORE the
//!   ledger is called, and is `InDoubt` until a final ledger answer is recorded;
//! * any unclear outcome stays `InDoubt`; a retry re-sends byte-identical arguments, which the
//!   ledger deduplicates (`Duplicate` carries the original block index);
//! * nothing after the ledger call can trap or panic.

use crate::types::*;
use candid::{Nat, Principal};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};
use std::cell::{Cell, RefCell};

#[allow(async_fn_in_trait)]
pub trait Ledger {
    async fn fee(&self) -> Result<u64, String>;
    async fn balance_of(&self, account: Account) -> Result<u64, String>;
    /// Outer `Err`: the call itself failed and the outcome is unknown.
    async fn transfer(&self, args: TransferArg) -> Result<Result<Nat, TransferError>, String>;
}

pub trait Store {
    fn save(&self, state: &State) -> Result<(), String>;
}

pub trait Clock {
    fn now_nanos(&self) -> u64;
}

pub struct Engine<L, S, C> {
    config: Config,
    self_id: Principal,
    ledger: L,
    store: S,
    clock: C,
    state: RefCell<State>,
    busy: Cell<bool>,
    /// The last durable write failed; flushed before the next mutating call.
    dirty: Cell<bool>,
}

struct BusyGuard<'a>(&'a Cell<bool>);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

fn is_definitive_refusal(e: &TransferError) -> bool {
    matches!(
        e,
        TransferError::BadFee { .. }
            | TransferError::BadBurn { .. }
            | TransferError::InsufficientFunds { .. }
            | TransferError::CreatedInFuture { .. }
            | TransferError::TemporarilyUnavailable
            | TransferError::GenericError { .. }
    )
}

impl<L: Ledger, S: Store, C: Clock> Engine<L, S, C> {
    pub fn new(
        config: Config,
        self_id: Principal,
        ledger: L,
        store: S,
        clock: C,
        state: State,
    ) -> Self {
        Self {
            config,
            self_id,
            ledger,
            store,
            clock,
            state: RefCell::new(state),
            busy: Cell::new(false),
            dirty: Cell::new(false),
        }
    }

    pub fn state(&self) -> State {
        self.state.borrow().clone()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn is_busy(&self) -> bool {
        self.busy.get()
    }

    pub fn source_account(&self) -> Account {
        Account {
            owner: self.self_id,
            subaccount: None,
        }
    }

    fn authorize(&self, caller: Principal) -> Result<(), RecoveryError> {
        if caller == Principal::anonymous() || caller != self.config.authorized_caller {
            return Err(RecoveryError::Unauthorized);
        }
        Ok(())
    }

    fn acquire(&self) -> Result<BusyGuard<'_>, RecoveryError> {
        if self.busy.replace(true) {
            return Err(RecoveryError::Busy);
        }
        Ok(BusyGuard(&self.busy))
    }

    fn persist(&self) -> Result<(), String> {
        let r = self.store.save(&self.state.borrow());
        self.dirty.set(r.is_err());
        r
    }

    fn flush_if_dirty(&self) -> Result<(), RecoveryError> {
        if self.dirty.get() {
            self.persist()
                .map_err(|message| RecoveryError::StorageError { message })?;
        }
        Ok(())
    }

    /// Sends a new operation to the ledger.
    pub async fn transfer(
        &self,
        caller: Principal,
        req: TransferRequest,
    ) -> Result<TransferOk, RecoveryError> {
        self.authorize(caller)?;
        if req.amount_e8s == 0 {
            return Err(RecoveryError::ZeroAmount);
        }
        if req.manifest_tag.len() != MANIFEST_TAG_LEN {
            return Err(RecoveryError::InvalidManifestTag);
        }
        if req.expected_fee_e8s != self.config.fee_e8s {
            return Err(RecoveryError::UnexpectedFee {
                expected_e8s: self.config.fee_e8s,
                requested_e8s: req.expected_fee_e8s,
            });
        }
        let _guard = self.acquire()?;
        self.flush_if_dirty()?;
        {
            let st = self.state.borrow();
            if let Some(op) = st.unresolved() {
                return Err(RecoveryError::UnresolvedOperation {
                    operation_id: op.id,
                });
            }
            if st.next_operation_id != req.expected_operation_id {
                return Err(RecoveryError::OperationIdMismatch {
                    expected_next: st.next_operation_id,
                    requested: req.expected_operation_id,
                });
            }
            if st.operations.len() >= MAX_OPERATIONS {
                return Err(RecoveryError::OperationLimitReached);
            }
        }

        let ledger_fee = self
            .ledger
            .fee()
            .await
            .map_err(|message| RecoveryError::LedgerQueryFailed { message })?;
        if ledger_fee != self.config.fee_e8s {
            return Err(RecoveryError::UnexpectedLedgerFee {
                expected_e8s: self.config.fee_e8s,
                actual_e8s: ledger_fee,
            });
        }
        let balance = self
            .ledger
            .balance_of(self.source_account())
            .await
            .map_err(|message| RecoveryError::LedgerQueryFailed { message })?;
        let required = req.amount_e8s.checked_add(self.config.fee_e8s).ok_or(
            RecoveryError::InsufficientFunds {
                balance_e8s: balance,
                required_e8s: u64::MAX,
            },
        )?;
        if balance < required {
            return Err(RecoveryError::InsufficientFunds {
                balance_e8s: balance,
                required_e8s: required,
            });
        }

        // The state cannot have changed: `busy` was held across the awaits above.
        let id = self.state.borrow().next_operation_id;
        let op = Operation {
            id,
            amount_e8s: req.amount_e8s,
            fee_e8s: self.config.fee_e8s,
            created_at_time_nanos: self.clock.now_nanos(),
            memo: make_memo(id, &req.manifest_tag),
            attempts: 1,
            status: Status::InDoubt {
                last_error: "submitted; no ledger answer recorded yet".to_string(),
            },
        };
        {
            let mut st = self.state.borrow_mut();
            st.operations.push(op);
            st.next_operation_id = id.saturating_add(1);
        }
        if let Err(message) = self.persist() {
            let mut st = self.state.borrow_mut();
            st.operations.pop();
            st.next_operation_id = id;
            self.dirty.set(false);
            return Err(RecoveryError::StorageError { message });
        }
        self.submit(id).await
    }

    /// Re-sends the unresolved operation with byte-identical arguments.
    pub async fn retry_pending(
        &self,
        caller: Principal,
        operation_id: u64,
    ) -> Result<TransferOk, RecoveryError> {
        self.authorize(caller)?;
        let _guard = self.acquire()?;
        self.flush_if_dirty()?;
        {
            let mut st = self.state.borrow_mut();
            let now = self.clock.now_nanos();
            let Some(op) = st
                .operations
                .iter_mut()
                .find(|o| matches!(o.status, Status::InDoubt { .. }))
            else {
                return Err(RecoveryError::NoPendingOperation);
            };
            if op.id != operation_id {
                return Err(RecoveryError::OperationNotPending { operation_id });
            }
            let age = now.saturating_sub(op.created_at_time_nanos);
            if age > RETRY_WINDOW_NANOS {
                return Err(RecoveryError::RetryWindowExpired {
                    operation_id,
                    age_nanos: age,
                });
            }
            op.attempts = op.attempts.saturating_add(1);
        }
        if let Err(message) = self.persist() {
            if let Some(op) = self
                .state
                .borrow_mut()
                .operations
                .iter_mut()
                .find(|o| o.id == operation_id)
            {
                op.attempts = op.attempts.saturating_sub(1);
            }
            self.dirty.set(false);
            return Err(RecoveryError::StorageError { message });
        }
        self.submit(operation_id).await
    }

    /// Declares an in-doubt operation as not executed. Only possible once the ledger would reject
    /// a replay as too old; the operator must first have verified on the ledger that no matching
    /// transfer exists.
    pub fn abandon_pending(
        &self,
        caller: Principal,
        operation_id: u64,
    ) -> Result<(), RecoveryError> {
        self.authorize(caller)?;
        let _guard = self.acquire()?;
        self.flush_if_dirty()?;
        let previous;
        {
            let mut st = self.state.borrow_mut();
            let now = self.clock.now_nanos();
            let Some(op) = st
                .operations
                .iter_mut()
                .find(|o| matches!(o.status, Status::InDoubt { .. }))
            else {
                return Err(RecoveryError::NoPendingOperation);
            };
            if op.id != operation_id {
                return Err(RecoveryError::OperationNotPending { operation_id });
            }
            let age = now.saturating_sub(op.created_at_time_nanos);
            if age < ABANDON_AFTER_NANOS {
                return Err(RecoveryError::AbandonTooEarly {
                    operation_id,
                    remaining_nanos: ABANDON_AFTER_NANOS - age,
                });
            }
            previous = std::mem::replace(&mut op.status, Status::Abandoned);
        }
        if let Err(message) = self.persist() {
            if let Some(op) = self
                .state
                .borrow_mut()
                .operations
                .iter_mut()
                .find(|o| o.id == operation_id)
            {
                op.status = previous;
            }
            self.dirty.set(false);
            return Err(RecoveryError::StorageError { message });
        }
        Ok(())
    }

    /// Calls the ledger for a recorded operation and records the answer. Must be called with
    /// `busy` held and the operation already persisted as `InDoubt`.
    async fn submit(&self, id: u64) -> Result<TransferOk, RecoveryError> {
        let args = {
            let st = self.state.borrow();
            let Some(op) = st.operations.iter().find(|o| o.id == id) else {
                return Err(RecoveryError::OperationNotPending { operation_id: id });
            };
            TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: self.config.destination,
                    subaccount: None,
                },
                amount: Nat::from(op.amount_e8s),
                fee: Some(Nat::from(op.fee_e8s)),
                memo: Some(Memo::from(op.memo.clone())),
                created_at_time: Some(op.created_at_time_nanos),
            }
        };
        let result = self.ledger.transfer(args).await;
        self.record_result(id, result)
    }

    fn record_result(
        &self,
        id: u64,
        result: Result<Result<Nat, TransferError>, String>,
    ) -> Result<TransferOk, RecoveryError> {
        let outcome = {
            let mut st = self.state.borrow_mut();
            let Some(op) = st.operations.iter_mut().find(|o| o.id == id) else {
                return Err(RecoveryError::OperationNotPending { operation_id: id });
            };
            let first_attempt = op.attempts <= 1;
            match result {
                Ok(Ok(block_index)) => {
                    op.status = Status::Completed {
                        block_index: block_index.clone(),
                        duplicate: false,
                    };
                    Ok(TransferOk {
                        operation_id: id,
                        block_index,
                        duplicate: false,
                    })
                }
                Ok(Err(TransferError::Duplicate { duplicate_of })) => {
                    op.status = Status::Completed {
                        block_index: duplicate_of.clone(),
                        duplicate: true,
                    };
                    Ok(TransferOk {
                        operation_id: id,
                        block_index: duplicate_of,
                        duplicate: true,
                    })
                }
                // Only a first attempt's refusal proves nothing was executed: on a retry the
                // original may have executed and the ledger may report a different error first.
                Ok(Err(e)) if first_attempt && is_definitive_refusal(&e) => {
                    op.status = Status::Failed {
                        reason: format!("{e:?}"),
                    };
                    Err(RecoveryError::Ledger { error: e })
                }
                Ok(Err(e)) => {
                    let message = format!("ledger answered {e:?}; outcome not proven");
                    op.status = Status::InDoubt {
                        last_error: message.clone(),
                    };
                    Err(RecoveryError::Ambiguous {
                        operation_id: id,
                        message,
                    })
                }
                Err(message) => {
                    op.status = Status::InDoubt {
                        last_error: message.clone(),
                    };
                    Err(RecoveryError::Ambiguous {
                        operation_id: id,
                        message,
                    })
                }
            }
        };
        // A failure here is remembered (`dirty`) and retried before the next mutating call; the
        // in-memory state stays authoritative and the answer is still returned.
        let _ = self.persist();
        outcome
    }
}
