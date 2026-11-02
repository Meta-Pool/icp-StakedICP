# neuron-audit operator runbook

`neuron-audit` keeps its audit commands read-only and adds an explicitly gated,
controller-verified `StartDissolving` workflow. `StartDissolving` begins the
neuron's dissolve countdown; it does not disburse ICP or transfer tokens.
`RecoverDisburse` remains a separate legacy capability with its existing safeguards.

## Canonical neuron inventory (`audit-in/neurons.txt`)

`audit-in/neurons.txt` is the canonical list of every known neuron ID: one `u64`
per line, numerically sorted, deduplicated, regardless of owner, accessibility or
dissolve state. It lists *candidates* only; it is never authorization evidence.

1. **Maintain** the canonical file. Entries are never removed by tooling; a
   malformed canonical file makes `sync` fail without touching it.
2. **Synchronize** when new sources appear (offline, no NNS access, atomic write,
   idempotent). Run from the repo root or the crate directory:

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- inventory sync --include-history
# extra explicit sources: --source bash-array=recovery/2026-10-22/check-neurons.sh
#   kinds: bash-array|csv|snapshot|control-report|controller-trace|disburse
# preview only: --dry-run
```

   `--include-history` reads a fixed trusted set (recovery `check-neurons.sh`
   `NEURONS=( ... )` array, `neurons-audit.txt`, `audit-out` snapshots, CSV,
   control report, controller trace, disburse records) and extracts IDs only from
   named neuron-ID fields/columns. Malformed records are reported, not imported.
   The deterministic report with per-source counts, duplicates, unique-to-source
   IDs and per-ID provenance is `audit-out/inventory-report.md`.
3. **Audit** the inventory with fresh authenticated reads (`audit --ids-file audit-in/neurons.txt ...`).
4. **Plan** from the canonical inventory (`--ids-file` is optional and defaults to it):
5. **Keep separate**: controller verification (the plan) and dissolution
   execution (`dissolve start` / `batch`) are distinct operations.

## Build and prepare a fresh plan

Run from the repository root. The planner defaults to the canonical
`tools/neuron-audit/audit-in/neurons.txt` (override with `--ids-file`). It
fetches fresh signed `list_neurons` responses and includes only full records
whose controller equals the live Oracle principal. Hotkeys and info-only records
never qualify.

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- dissolve plan \
  --out-dir audit-out --owner-pem -
```

Inspect the generated `audit-out/dissolve/plan-*.json`. Review the eligible
IDs, amounts, delays, expected dates, exclusions and `plan_sha256`. Keep this
plan immutable. A later run with a new live state should make a new plan.

## Execute one neuron

Select one reviewed ID from the eligible list. The operator must explicitly
provide `--execute`. Example (replace the ID and plan path):

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- dissolve start \
  --neuron-id 16136654443876485299 \
  --plan audit-out/dissolve/plan-YYYYMMDDTHHMMSSZ.json \
  --owner-pem - --execute
```

The command rechecks signing-canister ownership and key identity, then fetches
the neuron's current full record. It requires the Oracle to be the controller
and the state to be locked. Before submitting, it writes a create-only intent
record under `audit-out/dissolve/journal/`. It submits exactly one
`manage_neuron(Configure(StartDissolving))`, decodes the Governance result,
and reads the neuron again. Do not rerun after an intent exists without a
result file. An ambiguous outcome must be reconciled first.

Verify independently with the existing inspect command against the ID after
the call. Inspect the journal result as well; a successful Governance reply
alone is not the final verification.

## Batch execution and recovery

### Reconciling a mis-classified result

Early runs decoded Governance's `Configure : record {}` reply incorrectly and
journaled `governance_rejected` / `missing command response` for neurons that
were in fact dissolving. This is fixed. To reconcile such a journal entry
(read-only: one signed `list_neurons` query, no update), run:

```sh
dfx identity export sticpowner | cargo run --manifest-path tools/neuron-audit/Cargo.toml -- \
  dissolve reconcile --neuron-id <ID> --plan audit-out/dissolve/plan-YYYYMMDDTHHMMSSZ.json \
  --owner-pem - --out-dir audit-out
```

It refuses anything other than that exact mis-classification and writes a
create-only `<plan>-<id>.reconciled.json`; `start` and `batch` then skip the neuron.

Batch is sequential and requires both explicit flags. Use a protected PEM file
for repeatable per-neuron authentication (batch rejects `--owner-pem -`):

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- dissolve batch \
  --plan audit-out/dissolve/plan-YYYYMMDDTHHMMSSZ.json \
  --owner-pem /secure/path/owner.pem --execute --confirm-batch
```

The command stops at the first operation not verified as successful. Verified
successful results are skipped on resume. An intent without a result or a
result marked unknown blocks a repeat. Reconcile the live neuron with a fresh
read and the journal before taking any further operator action. Already
dissolving or dissolved neurons are recorded as skipped. Never delete or edit
journal files to bypass these checks.

## Final audit record

Retain the plan, its hash, every write-once `*.intent.json` and `*.result.json`,
and a fresh post-operation `inspect` output for each attempted ID. Report
successful, skipped, rejected, unknown and unattempted IDs from those records.
No call in this workflow disburses or transfers ICP.

## Verification boundary

Offline tests cover payload encoding/decoding, the exact signer permission,
eligibility classification and journal write-once behavior. A real NNS
environment is still required to verify the deployed Governance response
shape, signing-canister availability, replica certification/polling and the
on-chain resulting state. Do not use a mainnet update during development or
testing.

## Recovering liquid ICP from the `deposits` canister (`deposit …`)

Moves ICP held by canister `hnwvc-lyaaa-aaaal-aaf6q-cai` (ledger account
`0c5e0de7…32ed`, 942.33666604 ICP verified 2026-11-02) to the Meta Pool wallet
`nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae`
(account `2c4f8102…ac26`). This is a **ledger transfer**, unlike `recover-disburse`, which is a
Governance `Disburse` of neuron stake. Neurons and their dissolve state are never touched.

### Architecture

* `recovery-canister/` – small Rust canister (`ic-cdk 0.20`, `icrc-ledger-types 0.2`). Source
  account, destination (principal + default subaccount), authorized caller (`sticpowner`), ledger
  and fee (10 000 e8s) are compile-time constants. Endpoints: `transfer`, `retry_pending`,
  `abandon_pending` (updates, caller-restricted), `get_state`, `get_config` (queries). There is no
  recipient parameter and no generic wallet/withdraw interface.
* Safety engine (`src/engine.rs`, ledger/storage/clock behind traits, unit-tested with a mock ledger):
  exact `u64` e8s arithmetic with checked ops; amount > 0 and `amount + fee <= balance`; fee must
  equal the constant *and* the live `icrc1_fee`; `expected_operation_id` must equal the next id
  (replays of an old request are rejected); a re-entrancy guard rejects overlapping transfers;
  the operation is persisted as `InDoubt` **before** the ledger call, with fixed `created_at_time`
  and a memo (op id + manifest tag). Retries re-send identical arguments so the ledger
  deduplicates (`Duplicate` ⇒ success, paid once). Only a first-attempt definitive refusal is
  recorded `Failed`. No trapping assertions after the call is started; stable-memory record is
  versioned and validated.
* `src/deposit_manifest.rs` (pure) and `src/deposit.rs` (I/O) in the CLI. The CLI compiles
  `recovery-canister/src/types.rs` directly, so constants and wire types cannot drift.
* Approval flow is the existing one: dry run by default; `--execute` needs
  `--approve-payload-sha256` of the exact Candid payload printed by the dry run; a create-only
  intent journal is written before sending; reruns refuse when an intent exists.

### Threat model and assumptions

* Only `sticpowner` may call the recovery canister; the destination cannot be changed by a caller.
* **Other controllers keep full administrative authority** over the canister (10 controllers at
  observation time). Any of them can upgrade/reinstall/stop it, change settings, or drain it.
  This workflow does not change controllers or settings and does not protect against them.
* The tool refuses non-mainnet URLs (built-in IC root key), any other canister, destination,
  ledger, identity, or module hash than the manifest's.
* Assumption: ICP ledger deduplicates identical `icrc1_transfer` arguments for 24 h (+drift). The
  canister retries only within 12 h and allows `abandon_pending` only after 25 h.
* The Wasm hash is only reproducible with the same toolchain; the manifest pins the hash of the
  file you built and review.

### Build and test

```bash
tools/neuron-audit/recovery-canister/build.sh     # prints size + sha256; writes target/wasm32-unknown-unknown/release/recovery_canister.wasm
(cd tools/neuron-audit/recovery-canister && cargo test && cargo clippy --all-targets)
(cd tools/neuron-audit && cargo test && cargo clippy --all-targets)
```

PocketIC integration tests are **not** included (they need a downloaded server binary and ICP
ledger Wasm); behavior against the ledger is covered by the mock-ledger tests only. Confirm
default-account origin on mainnet with the 0.1 ICP test, which is why it comes first.

### Command classes

| Class | Commands | Effect |
|---|---|---|
| Read-only | `deposit status`, `deposit verify`, `deposit reconcile` | queries; with `--owner-pem` one `canister_status` call (no change) |
| Local preparation | `deposit prepare` | writes a manifest file (create-only) |
| Installation | `deposit install` | `install_code` mode `install` only, only into the manifest canister |
| Irreversible | `deposit transfer` | canister sends ICP |

### Manifest (abridged)

`deposit prepare --kind test|final` writes JSON `{ "body": {...}, "manifest_sha256": "…" }`; the hash
is SHA-256 of the compact JSON of `body` and is recomputed on every load. Body contains: kind,
network (`ic`, URL), observed_at (unix + UTC), source (canister, account id, balance, pre-install
module hash `null`, cycles, controllers snapshot, settings hash), destination (principal, account id,
balance), authorized caller, ledger + fee, wasm (sha256, size), install (mode `install`, target),
and transfer (operation id, amount, fee, total debit, expected source/destination balances after).
The transfer payload carries the first 16 bytes of the manifest hash as memo tag, so its own
hash is printed at execution time instead of being stored.
Test: 10 000 000 e8s (debit 10 010 000). Manifests older than 1 h are rejected.

### Mainnet preflight checklist

1. `deposit status --owner-pem <sticpowner.pem>`: Running, module hash `None`, `sticpowner` listed as
   controller, fee 10 000, balances as expected, derived accounts "verified".
2. Review the controller list; record that others retain authority.
3. Build the Wasm, record sha256 and review the source at the commit being deployed.
4. `deposit prepare` → read the manifest; `deposit verify --stage install`.
5. Nothing in the checks may be waved through: any `BLOCKED` line stops the procedure.

### Procedure: first 0.1 ICP test

```bash
cd tools/neuron-audit
recovery-canister/build.sh
cargo run -- deposit status --owner-pem sticpowner.pem
cargo run -- deposit prepare --kind test --wasm recovery-canister/target/wasm32-unknown-unknown/release/recovery_canister.wasm \
  --owner-pem sticpowner.pem --out audit-out/deposit/test-manifest.json
cargo run -- deposit verify --manifest audit-out/deposit/test-manifest.json --stage install --owner-pem sticpowner.pem
# Manual installation (dry run first, then exactly the printed hash):
cargo run -- deposit install --manifest audit-out/deposit/test-manifest.json --wasm <wasm> --owner-pem sticpowner.pem
cargo run -- deposit install ... --execute --approve-payload-sha256 <hash printed above>
cargo run -- deposit verify   --manifest audit-out/deposit/test-manifest.json --stage transfer --owner-pem sticpowner.pem
cargo run -- deposit transfer --manifest audit-out/deposit/test-manifest.json --owner-pem sticpowner.pem
cargo run -- deposit transfer ... --execute --approve-payload-sha256 <hash printed above>
cargo run -- deposit reconcile --manifest audit-out/deposit/test-manifest.json
```

Install checks (before and right before sending): module hash `None`, controllers/settings snapshot
equal, Running, cycles ≥ 1T. After: module hash equals the Wasm, controllers/settings unchanged,
initial recovery state. Never use `reinstall`/`upgrade` (the tool cannot encode them).

### Ledger reconciliation

`deposit reconcile` compares the canister's operation record, the ledger block (sender = source
account, recipient = destination account, amount, fee) and both balances. Verdicts: `Reconciled`,
`NotSubmitted`, `Failed`, `Abandoned`, `InDoubt`, `Discrepancy`, `Unverified`. Exit code 0 only for
`Reconciled`. A report is written under `audit-out/deposit/`.

### Final transfer

Only after the test is `Reconciled`. Build a **new** manifest (`deposit prepare --kind final`,
operation id taken from the canister's `get_state`, balances default to the post-test values; pass
`--expected-balance-e8s` explicitly if the source changed) and repeat verify → dry run → separate
approval → execute → reconcile. The amount is the current balance minus the fee; never reuse the
test manifest. A different manifest means a different memo tag and operation id.

### Failure and recovery

* **Install failed/timeout:** do not retry. Run `deposit verify --stage install`/`status`; if the
  module hash equals the Wasm, it succeeded. Otherwise the intent journal blocks resending: inspect
  it, then decide manually.
* **Transfer: no reply/timeout:** do not rerun `deposit transfer` (the journal refuses it anyway).
  Run `deposit reconcile`. `InDoubt` ⇒ `dfx canister call hnwvc-lyaaa-aaaal-aaf6q-cai retry_pending '(N : nat64)' --network ic --identity sticpowner`
  (N = operation id; allowed within 12 h; identical args ⇒ ledger dedup).
* **`Failed`:** ledger refused definitively; nothing moved. Prepare a fresh manifest.
* **`Abandoned`:** only possible after 25 h; check balances before preparing anything new.
* **`Discrepancy`:** stop. Compare the block on the ledger dashboard before any action.

### Detecting an already-submitted transfer before retrying

1. `audit-out/deposit/journal/transfer-<manifest_sha>.intent.json` exists ⇒ it was attempted.
2. `dfx canister call hnwvc-lyaaa-aaaal-aaf6q-cai get_state --query --network ic` lists every
   operation with status, attempts and block index (authoritative).
3. `deposit status` shows the same state plus both ledger balances; the source balance must have
   dropped by amount + fee only if a block exists.
4. Look up the block index on the ledger. Only if the canister reports no record for the operation
   id *and* the balances are unchanged is nothing submitted.
