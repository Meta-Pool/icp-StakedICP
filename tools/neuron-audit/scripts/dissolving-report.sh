#!/usr/bin/env bash
# Read-only: anonymous get_neuron_info for every ID in audit-in/neurons.txt.
# Writes a Markdown table of neurons currently dissolving (state = 2) with stake and exact
# dissolution date. Never signs or submits anything.
set -euo pipefail

CRATE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$CRATE/../.." && pwd)"
IDS="${1:-$CRATE/audit-in/neurons.txt}"
OUT="${2:-$CRATE/audit-out/dissolving-neurons.md}"
GOV="rrkah-fqaaa-aaaaa-aaaaq-cai"

rows="$(mktemp)"; trap 'rm -f "$rows"' EXIT
total=0; n_diss=0; n_locked=0; n_done=0; n_other=0; n_err=0; errs=""

field() { sed -nE "s/.*[^a-z_]$1 = ([0-9_]+) :.*/\1/p" <<<"$2" | head -1 | tr -d '_'; }

while read -r id; do
  [ -z "$id" ] && continue
  out="$(dfx canister call --network ic --identity anonymous --query \
    --candid "$REPO/candid/nns-governance.did" "$GOV" \
    get_neuron_info "($id : nat64)" 2>&1 || true)"
  st="$(field state "$out")"; stake="$(field stake_e8s "$out")"
  dly="$(field dissolve_delay_seconds "$out")"; ret="$(field retrieved_at_timestamp_seconds "$out")"
  if ! grep -q 'Ok = record' <<<"$out" || [ -z "$st" ] || [ -z "$stake" ] || [ -z "$dly" ] || [ -z "$ret" ]; then
    n_err=$((n_err+1)); errs="$errs $id"; continue
  fi
  case "$st" in
    2) n_diss=$((n_diss+1)); total=$((total+stake))
       when=$((ret+dly))
       printf '%s|%s|%s|%s|%s\n' "$when" "$id" "$stake" "$dly" "$ret" >>"$rows" ;;
    1) n_locked=$((n_locked+1)) ;;
    3) n_done=$((n_done+1)) ;;
    *) n_other=$((n_other+1)) ;;
  esac
done <"$IDS"

mkdir -p "$(dirname "$OUT")"
{
  echo "# Neurons currently dissolving (on-chain, anonymous get_neuron_info)"
  echo
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')  |  Governance: $GOV"
  echo "Dissolution date = retrieved_at_timestamp_seconds + dissolve_delay_seconds (state = 2)."
  echo
  echo "| # | Neuron ID | Stake (ICP) | Dissolves on (UTC) | Days left |"
  echo "|---|---|---|---|---|"
  i=0
  sort -t'|' -k1,1n -k2,2n "$rows" | while IFS='|' read -r when id stake dly ret; do
    i=$((i+1))
    printf '| %s | %s | %s | %s | %s |\n' "$i" "$id" \
      "$(awk -v s="$stake" 'BEGIN{printf "%.8f", s/1e8}')" \
      "$(date -u -r "$when" '+%Y-%m-%d %H:%M:%S')" "$((dly/86400))"
  done
  echo
  echo "**Dissolving: $n_diss neurons, total $(awk -v s="$total" 'BEGIN{printf "%.8f", s/1e8}') ICP**"
  echo
  echo "Not in this table: locked/not dissolving (state 1): $n_locked; dissolved (state 3): $n_done; other state: $n_other; query errors: $n_err${errs:+ ($errs )}."
} >"$OUT"
echo "Wrote $OUT"
cat "$OUT"
