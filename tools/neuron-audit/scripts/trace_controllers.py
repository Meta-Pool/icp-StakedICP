#!/usr/bin/env python3
"""Read-only controller-origin tracing for NNS neurons the Oracle cannot read.

Uses only anonymous queries (ICP index + ledger via `dfx --identity anonymous`)
plus offline hashing. Nothing is signed, nothing is submitted, no key is read.

Method: an NNS neuron's stake account is
  AccountId(governance, SHA256(0x0c "neuron-stake" || controller || memo_be))
so for every candidate principal we recompute that account for each outgoing
funding transfer (memo != 0) from the candidate's own ledger account. A match
proves which principal was the controller at claim time. Split children carry
memo == their created_timestamp_seconds and are linked to the parent account
that paid for them on the ledger.

Usage (from tools/neuron-audit):
  python3 scripts/trace_controllers.py [EXTRA_NEURON_ID ...]
Writes audit-out/controller-trace.json.
"""
import base64, datetime, glob, hashlib, json, os, re, subprocess, sys, zlib

GOV = "rrkah-fqaaa-aaaaa-aaaaq-cai"
DEPOSITS_ACCT = "0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT = os.path.join(ROOT, "tools", "neuron-audit", "audit-out")
INDEX_DID = os.path.join(HERE, "icp-index.did")

# Historical deploy owners (git: scripts/deploy.sh), 2023 signing owner, local dfx identities, Oracle.
CANDIDATES = {
    "ckbyu-bzwwp-bxvwo-ewhjd-7ewsx-7wux3-c3foy-gp62f-enftx-nec3u-wqe": "historical deposits owner #2 (git scripts/deploy.sh)",
    "dtwfm-dtbib-y277g-oeali-iu4z4-m66x5-lofpb-oytcd-ursw2-2ne77-3qe": "historical deposits owner #3 (git scripts/deploy.sh)",
    "b66ir-rprad-rut4a-acjje-naq3d-ymndg-itex7-47hrz-vvzqy-3le4a-eae": "historical deposits owner #1 (git scripts/deploy.sh)",
    "m7vk4-yvozh-hdrvf-q7rn6-amgjb-4rfue-onhmm-i5m2t-k462c-u5nbe-sqe": "historical signing-canister owner (git scripts/deploy.sh)",
    "xijvt-cnjre-6zl3s-rjwnh-r2raw-oxemw-7lber-xgshh-sj7ny-alhap-rqe": "Oracle ECDSA principal (usable today via signing canister)",
    "pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe": "local dfx identity sticpowner (signing owner today)",
    "k3rg2-mzp3m-wfhcu-isim6-nj52a-vsklg-mpkik-qa6hb-ta2r4-vtu6h-eae": "local dfx identity default",
    "uuat4-5iv5w-j7v6s-tlwqa-56jzr-xmo4l-2h22z-conrm-uj4ea-uwsy7-oae": "local dfx identity metaPool",
    "qynmo-i7qti-5rth2-uo7f5-5cw7v-ngd4h-e5wh2-be5jy-vxgqh-xjasg-uae": "local dfx identity testICP",
}


def p2b(t):
    s = t.replace("-", "").upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))[4:]


def acct(pb, sub=b"\0" * 32):
    h = hashlib.sha224(b"\x0aaccount-id" + pb + sub).digest()
    return (zlib.crc32(h).to_bytes(4, "big") + h).hex()


def neuron_acct(ctrl, memo):
    sub = hashlib.sha256(b"\x0cneuron-stake" + ctrl + memo.to_bytes(8, "big")).digest()
    return acct(p2b(GOV), sub)


def dfx(candid, canister, method, arg):
    r = subprocess.run(["dfx", "canister", "--network", "ic", "--identity", "anonymous", "call", "--query",
                        "--candid", candid, canister, method, arg], capture_output=True, text=True, cwd=ROOT)
    return r.stdout


def n(s):
    return int(s.replace("_", ""))


def iso(sec):
    return datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def txs(account):
    out = dfx(INDEX_DID, "qhbym-qaaaa-aaaaa-aaafq-cai", "get_account_identifier_transactions",
              f'(record {{ max_results = 500 : nat64; start = null; account_identifier = "{account}" }})')
    res = []
    for p in re.split(r"record \{\s*id = ", out)[1:]:
        op = re.search(r"(TransferFrom|Transfer|Mint|Burn|Approve) = record", p)
        f, t = re.search(r'from = "(\w+)"', p), re.search(r'to = "(\w+)"', p)
        am = re.search(r"amount = record \{\s*e8s = ([\d_]+)", p)
        ts = re.search(r"timestamp = opt record \{\s*timestamp_nanos = ([\d_]+)", p)
        res.append(dict(block=n(p.split(" ")[0]), op=op and op.group(1), memo=n(re.search(r"memo = ([\d_]+)", p).group(1)),
                        frm=f and f.group(1), to=t and t.group(1), e8s=am and n(am.group(1)), ts=ts and n(ts.group(1)) // 10**9))
    return res


def balance(account):
    out = dfx(os.path.join(ROOT, "candid", "nns-ledger.did"), "ryjl3-tyaaa-aaaaa-aaaba-cai", "account_balance_dfx",
              f'(record {{ account = "{account}" }})')
    return n(re.search(r"e8s = ([\d_]+)", out).group(1))


def neuron_info(nid):
    out = dfx(os.path.join(ROOT, "candid", "nns-governance.did"), GOV, "get_neuron_info", f"({nid} : nat64)")
    g = lambda k: n(re.search(k + r" = ([\d_]+)", out).group(1))
    return dict(created=g("created_timestamp_seconds"), stake=g("stake_e8s"), state=g("state"))


def main():
    snap = json.load(open(sorted(glob.glob(os.path.join(OUT, "snapshots", "*.json")))[-1]))
    nrs = {int(x["neuron_id"]): x for x in snap["neurons"]}
    for i in [int(a) for a in sys.argv[1:]]:  # IDs found in git history but absent from the snapshot
        if i not in nrs:
            inf = neuron_info(i)
            nrs[i] = dict(neuron_id=str(i), status="not_in_snapshot", created_timestamp_seconds=inf["created"],
                          info_stake_e8s=inf["stake"], info_state=inf["state"], controller=None)
    by_created = {}
    for i, x in nrs.items():
        by_created.setdefault(x["created_timestamp_seconds"], []).append(i)

    roots, funders = [], {}
    for princ, why in CANDIDATES.items():
        pb = p2b(princ)
        wallet = acct(pb)
        found = [t for t in txs(wallet)
                 if t["op"] == "Transfer" and t["frm"] == wallet and t["memo"] and neuron_acct(pb, t["memo"]) == t["to"]]
        if found:
            funders[princ] = dict(wallet=wallet, why=why, neuron_stake_transfers=len(found))
        for t in found:
            roots.append(dict(controller=princ, memo=t["memo"], account=t["to"], block=t["block"], ts=t["ts"], neuron_id=None))

    # Claim follows funding within minutes: assign each funding transfer (in time order) to the earliest
    # unassigned neuron created at or after it, then sanity-check against the account balance below.
    taken = set()
    for r in sorted(roots, key=lambda r: r["ts"]):
        nxt = sorted((x["created_timestamp_seconds"], i) for i, x in nrs.items() if i not in taken and r["ts"] <= x["created_timestamp_seconds"] <= r["ts"] + 600)
        if nxt:
            r["neuron_id"] = nxt[0][1]
            taken.add(nxt[0][1])

    records, gone = {}, []
    for r in roots:
        r["balance_e8s"] = balance(r["account"])
        if r["neuron_id"] and r["balance_e8s"] != nrs[r["neuron_id"]]["info_stake_e8s"]:
            print(f"WARN neuron {r['neuron_id']}: ledger balance {r['balance_e8s']} != Governance stake {nrs[r['neuron_id']]['info_stake_e8s']} (fees/unrefreshed)", file=sys.stderr)
        if r["neuron_id"]:
            records[r["neuron_id"]] = dict(lineage="root", controller=r["controller"], parent=None,
                                           evidence=f"stake account {r['account'][:16]}… recomputes from (controller, memo {r['memo']}); funded in ledger block {r['block']}")
        for t in txs(r["account"]):
            if not (t["op"] == "Transfer" and t["frm"] == r["account"] and t["to"] != DEPOSITS_ACCT):
                continue
            if t["memo"] in by_created:
                for cid in by_created[t["memo"]]:
                    records[cid] = dict(lineage="split-child", controller=r["controller"], parent=r["neuron_id"],
                                        evidence=f"funded by Split transfer from parent account {r['account'][:16]}… (block {t['block']}, memo {t['memo']} = created_timestamp_seconds)")
            else:
                dis = [d for d in txs(t["to"]) if d["frm"] == t["to"] and d["to"] == DEPOSITS_ACCT]
                gone.append(dict(parent=r["neuron_id"], split_block=t["block"], split_utc=iso(t["ts"]), split_e8s=t["e8s"],
                                 balance_now_e8s=balance(t["to"]),
                                 disbursed_to_deposits=[dict(block=d["block"], utc=iso(d["ts"]), e8s=d["e8s"]) for d in dis]))

    rows = []
    for i, x in sorted(nrs.items(), key=lambda kv: kv[1]["created_timestamp_seconds"]):
        rec = records.get(i)
        if x["status"] == "full":
            cls, ctrl, why = "confirmed_controller", x["controller"], "Authenticated Oracle read the full record; controller field is the Oracle principal."
        elif rec:
            cls, ctrl, why = ("other_controller" if rec["lineage"] == "root" else "other_controller_inferred"), rec["controller"], rec["evidence"]
        else:
            cls, ctrl, why = "unknown", None, "No ledger lineage located; Governance does not disclose the controller of private neurons."
        rows.append(dict(neuron_id=str(i), created_utc=iso(x["created_timestamp_seconds"]), state=x["info_state"], stake_e8s=x["info_stake_e8s"],
                         snapshot_status=x["status"], classification=cls, controller=ctrl,
                         lineage=rec["lineage"] if rec else None, parent_neuron=rec["parent"] if rec else None, reason=why))
    report = dict(generated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  funders=funders, neurons=rows, split_children_no_longer_in_inventory=gone)
    os.makedirs(OUT, exist_ok=True)
    json.dump(report, open(os.path.join(OUT, "controller-trace.json"), "w"), indent=2)
    counts = {}
    for r in rows:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
    print(json.dumps(dict(funders=funders, counts=counts, gone=len(gone)), indent=1))


if __name__ == "__main__":
    main()
