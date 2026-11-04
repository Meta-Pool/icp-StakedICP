# Engineering Ledger Entry — Recovery of Liquid ICP from `deposits`

**Date:** 2026-11-02  
**Project:** `icp-StakedICP`  
**Branch:** `sticp-neuron-recovery` (the Codex report also references `feat/sticp-neuron-recovery`; verify the actual Git ref before linking the commit)  
**Tooling:** `tools/neuron-audit`, `tools/neuron-audit/recovery-canister`  
**Outcome:** **Liquid ICP recovered; `deposits` source account emptied and destination balance confirmed.**  
**Scope:** Liquid ICP on the ICP Ledger only. **NNS neuron stakes, dissolving schedules, and outstanding stICP liabilities are not settled by this operation itself.**

## Executive record

On 2026-11-02, we recovered the liquid ICP held at the default Ledger account of the `deposits` canister, after the application frontend had been retired and the original deposits logic was no longer needed. Meta Pool provided a destination principal and ICP account identifier to receive the recovered funds for pending stICP withdrawals. We verified that the recipient account was the default account derived from the supplied principal.

We installed a purpose-built Rust recovery Wasm **into the existing, initially empty `deposits` canister**, preserving its canister principal and controllers. After local tests, PocketIC integration against an ICP Ledger Wasm, a read-only mainnet preflight, and an explicitly approved install, we performed a 0.1 ICP real test transfer and reconciled it against Ledger block **39,998,015**. We then prepared a second manifest for the remaining funds. An intervening **+10,000 e8s** balance difference caused the first final-transfer attempt to be blocked before submission; we regenerated the manifest and completed the final operation. The final transaction's block index and reconciliation report were **not captured in the shared terminal output**. Its completion is evidenced by subsequent direct mainnet balance queries.

**Final balance checks, 2026-11-02 12:43 (user terminal):**

| Account | Before recovery | After recovery |
|---|---:|---:|
| `deposits` source | 942.33666604 ICP | **0.00000000 ICP** |
| Meta Pool destination | 0.50000000 ICP | **942.83656604 ICP** |

Total increase at destination: **942.33656604 ICP** (0.10000000 + 942.23656604). Two Ledger fees at 0.00010000 ICP each consumed **0.00020000 ICP**. Relative to the original source balance, these numbers reflect an **additional 0.00010000 ICP credited to source between the first test and the final transfer**. Its origin was not established.

## Identifiers and immutable evidence

| Purpose | Value |
|---|---|
| Existing source canister (`deposits`) | `hnwvc-lyaaa-aaaal-aaf6q-cai` |
| Source default account identifier | `0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed` |
| Native ICP Ledger canister | `ryjl3-tyaaa-aaaaa-aaaba-cai` |
| Authorized operator (`sticpowner`) | `pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe` |
| Recipient principal supplied by Meta Pool | `nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae` |
| Recipient default ICP account identifier | `2c4f810252eef78e5e81f15a086bc7b1fc5706bacbfa13fdf4e6c1fd9ae3ac26` |
| Recovery Wasm SHA-256 | `c655f851a139202ca36268ec9e6c3d695ad19654ff4c3aa2bcf3428c98826473` |
| Recovery Wasm size | 696,643 bytes |
| ICP Ledger test fixture revision | `d87954601e4b22972899e9957e800406a0a6b929` |
| ICP Ledger fixture `.wasm.gz` SHA-256 (locally computed) | `91b31bdf996e9b7885ef6ab996b7e0512f67d49f40320258d8697a5bd7148aa6` |

**Verification:** `dfx ledger account-id --of-principal <recipient-principal>` returned the exact account identifier supplied by Meta Pool; the analogous command confirmed the source account derives from `deposits`.

## Context and constraints

- `deposits` was **Running**, had **`Module hash: None`**, and contained enough cycles for installation. Its default Ledger account held 942.33666604 ICP before this recovery.
- The administrative identity `sticpowner` was among **10 controllers**. We preserved the controller list and canister settings; other controllers retained full administrative authority.
- A controller identity cannot simply use `dfx ledger transfer` to spend ICP in a canister-owned account. A transfer must originate from that canister, invoking `icrc1_transfer` with `from_subaccount: None`.
- Administrative approval was confirmed to use the retired `deposits` canister solely for recovery. A destination address alone had not been treated as sufficient approval before that confirmation.
- `recover-disburse` in the earlier audit tooling concerns **NNS neuron disbursements**; it is distinct from transferring liquid ICP held by `deposits`.

## Implementation

Codex added an independent `recovery-canister` crate and extended the host-side `neuron-audit` CLI. The canister fixes the source principal, authorized caller, ICP Ledger, destination principal/default subaccount, and expected fee. The host tool offers:

```text
deposit status       # read-only mainnet observation
deposit prepare      # create-only sealed JSON manifest
deposit verify       # compare manifest against live state
deposit install      # dry-run by default; explicitly gated install_code
deposit transfer     # dry-run by default; explicitly gated real transfer
deposit reconcile    # ledger block / canister state / balances
```

Key controls included integer e8s arithmetic; live fee and balance checks; one operation at a time via `BusyGuard`; persistence of `InDoubt` **before** the external Ledger call; fixed `created_at_time`/memo for deduplicated retries; detection of unresolved previous operations; strict Wasm hash/size and module hash checks; manifest sealing with SHA-256; a payload-specific `--approve-payload-sha256`; and create-only intent/result journals. The `install_code` call explicitly encoded mode **`install`** and targeted the pre-existing canister, not a new canister or a `reinstall`.

A manual code inspection covered `Engine::transfer`, `submit`, `record_result`, `authorize`, `acquire`, `persist`, `flush_if_dirty`, `deposit::install`, `encode_install`, and the principal validation checks in `check_live`. This was **a targeted review, not an independent exhaustive security audit**. In particular, classification of `GenericError` as a definitive initial refusal was identified as something worth hardening for future recoveries; no code change to that classification was documented during this session.

## Tests and staging

- Codex reported **28 recovery-canister tests** and **108 neuron-audit tests** passing; the user reran the suites successfully.
- The `wasm32-unknown-unknown` release Wasm was compiled and SHA-256 recorded.
- A basic PocketIC smoke test passed. PocketIC automatically downloaded server 9.0.3, and ran successfully on the user's Mac.
- A PocketIC test installed the **same compiled recovery Wasm** at the production `deposits` principal, on an isolated local instance, and verified `get_config`.
- A second PocketIC integration test used the downloaded native ICP Ledger Wasm with exact Ledger and source canister IDs, funded local accounts with **942.33666604 ICP** and **0.50000000 ICP**, transferred **0.10000000 ICP**, and checked the fee and balances.
- The local transfer returned **Ledger block 2** and a replay of the same operation did **not** transfer funds again.

Expected PocketIC balances after one transfer:

```text
source      942.23656604 ICP
recipient     0.60000000 ICP
fee           0.00010000 ICP
```

These were local simulations, not mainnet transfers.

## Mainnet sequence

### 1. Read-only inspection and identity setup

Confirmed source balance, owner principal, recipient principal/account correspondence, empty module hash, and controllers using `dfx` and `neuron-audit deposit status`.

`sticpowner` was stored in the **macOS Keychain**, not as `~/.config/dfx/identity/sticpowner/identity.pem`. For the CLI, an export was made to:

```text
~/.icp-recovery-private/sticpowner.pem
```

The containing directory was set to `0700`, the PEM to `0600`. **This is a sensitive private key; never commit, paste, archive with audit reports, or share it.** After verifying no further operations need it, remove the temporary plaintext export, keeping the Keychain identity.

### 2. Install into the existing `deposits` canister

Created and verified the first sealed manifest:

```text
audit-out/deposit/test-manifest.json
manifest SHA-256: b85bc83dcaff38bd808f7d73141757b5d3dc225427298d02eefad7fcff57f7e2
Wasm SHA-256:     c655f851a139202ca36268ec9e6c3d695ad19654ff4c3aa2bcf3428c98826473
```

The `deposit install` dry-run reported the exact `install_code` Candid payload SHA-256:

```text
4a742859c1b34ba6a459332de008a05802c6b3d44abd3c32389438f266d46dd4
```

After explicit `--execute` and hash approval, the CLI reported:

```text
INSTALLED AND VERIFIED
Module hash: c655f851a139202ca36268ec9e6c3d695ad19654ff4c3aa2bcf3428c98826473
Recovery state: next operation 1, 0 recorded
```

Controller list and settings were preserved; subsequent `deposit verify --stage transfer` returned `VERIFIED`.

### 3. Test transfer — operation 1

Authorized a dry-run with transfer payload SHA-256:

```text
8b0044f254a1d3dbcd0d1b785a9a830d499da3522d007285cbde19e137621c1c
```

Submitted **10,000,000 e8s (0.1 ICP)** plus **10,000 e8s fee** to the recipient. The CLI returned:

```text
operation 1, block 39_998_015, duplicate=false
Canister record: Completed
Ledger block: Verified
Source:      94233666604 -> 94223656604 e8s
Destination:    50000000 ->    60000000 e8s
VERDICT: Reconciled
```

Reconciliation report:

```text
audit-out/deposit/reconcile-b85bc83dcaff38bd808f7d73141757b5d3dc225427298d02eefad7fcff57f7e2-1793644655.json
```

### 4. First final manifest — rejected due to changed source balance

The initial final manifest used the post-test source balance **94,223,656,604 e8s**:

```text
audit-out/deposit/final-manifest.json
manifest SHA-256: 88934a202733875a5273841e3c97044824d38c66708a00cdc71950c394b57c71
planned transfer: 94,223,646,604 e8s + 10,000 e8s fee
payload SHA-256: 73deccbb7b715f335d826cdefa82bf5e51f05ac2bbee6549852e0e5263e7baee
```

At actual execution preflight, live source balance was **94,223,666,604 e8s**, i.e. **+10,000 e8s** beyond the manifest. The tool **blocked the operation and sent nothing**:

```text
BLOCKED: source balance is 94223666604 e8s,
manifest says 94223656604 e8s; prepare a new manifest
error: pre-transfer checks failed; nothing was sent
```

The precise cause of this 10,000 e8s credit was **not established**. Preserve this discrepancy for later Ledger-history reconciliation; do not invent an explanation.

### 5. Revised final manifest — operation 2

A new manifest used the observed balance, keeping the destination at 60,000,000 e8s:

```text
audit-out/deposit/final-manifest-v2.json
manifest SHA-256: 7162e7db2e82096efcfa31d04aec4151be5f8708802b8b5b0ca618b73e239a45
amount: 94,223,656,604 e8s = 942.23656604 ICP
fee: 10,000 e8s = 0.00010000 ICP
expected source after: 0 e8s
expected destination after: 94,283,656,604 e8s
```

`deposit verify --stage transfer` returned `VERIFIED`. Dry-run printed payload SHA-256:

```text
ba1292e62f0e9fc9fba4df307db0b7e89e9d40099ab8716ab61c3ff362eb21c9
```

The user proceeded with the final transfer. **The final transfer CLI receipt and block number were not supplied in the conversation**, so they must not be fabricated. Direct mainnet Ledger balance checks immediately afterward showed:

```text
dfx ledger balance <deposits-account> --network ic
0.00000000 ICP

dfx ledger balance <meta-pool-account> --network ic
942.83656604 ICP
```

Those final balances match the revised manifest exactly. The additional 0.0001 ICP source credit explains why total transferred is 942.33656604 ICP rather than the initially expected 942.33646604 ICP.

## Safe read-only verification commands

From `tools/neuron-audit`:

```bash
# Current source and recipient balances

dfx ledger balance \
  0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed \
  --network ic

dfx ledger balance \
  2c4f810252eef78e5e81f15a086bc7b1fc5706bacbfa13fdf4e6c1fd9ae3ac26 \
  --network ic

# Canister's persistent operation log (query)
dfx canister call hnwvc-lyaaa-aaaal-aaf6q-cai get_state \
  --query --network ic

# Inspect current recovery canister and balances
cargo run -- deposit status

# Reconcile revised final manifest; read-only
cargo run -- deposit reconcile \
  --manifest audit-out/deposit/final-manifest-v2.json
```

No replay, retry, install, upgrade, controller change, or further sweep should be attempted without new evidence and a new, independent authorization.

## Follow-up / retention checklist

- [x] Test transfer recorded `Completed` at block **39,998,015** and `Reconciled`.
- [x] Final source Ledger account observed at **0 ICP**.
- [x] Final destination Ledger account observed at **942.83656604 ICP**.
- [ ] Run read-only `deposit reconcile` for `final-manifest-v2.json`; archive its report and final block index if available.
- [ ] Investigate the **+10,000 e8s** between the test and final-transfer preflights using Ledger history.
- [ ] Retain manifests, journals, reconciliation JSON, Wasm hash, source revision/commit, and successful test logs in an access-controlled location.
- [ ] Remove the temporary exported PEM when no longer needed; do not delete the Keychain identity.
- [ ] Coordinate with Meta Pool: transfer of ICP to the designated wallet **does not itself prove** that each pending stICP withdrawal has been paid.
- [ ] Plan separate NNS neuron recovery/accounting; this entry does not cover neuron funds.
- [ ] Decide later whether to retire the recovery Wasm or canister. **Do not delete the canister solely because the Ledger account is empty:** the canister retains cycles and is part of the audit trail.

## Engineering lessons

1. **Canister-owned ICP is not controller-owned ICP.** The ledger sender was the canister's own principal, so a minimal canister-side transfer method was necessary.
2. **Keep identities stable.** Installing into the original empty canister retained its original account identifier; creating a new canister would not have moved those funds.
3. **An explicit approval hash is useful only with a fresh preflight.** The first large transfer was correctly blocked because the source balance differed by just 10,000 e8s.
4. **Persist intent before sending; reconcile after sending.** Responses can be lost independently of execution. Never infer failure solely from a timeout.
5. **A successful simulation is evidence, not permission.** PocketIC proved runtime behavior; mainnet still required checks, human authorization, and a controlled 0.1 ICP test.
6. **Keep each recovery scope separate.** Liquid ICP recovery succeeded; stICP claims and NNS neuron assets remain distinct operational/accounting problems.

---

**Status as of final recorded checks:** **Liquid `deposits` balance recovered and forwarded to the Meta Pool destination; source account 0 ICP.** The final Ledger block and corresponding final `Reconciled` output remain to be archived.
