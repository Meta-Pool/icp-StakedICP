```sh
dfx ledger balance --network ic

dfx canister call token balanceOf '(principal "hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe")'

dfx canister call deposits exchangeRate

dfx canister call deposits getDepositAddress
dfx canister call deposits getDepositSubaccount # use this with the front

dfx ledger transfer 8D564A3A41C374C80BB9AC7BF0E4DB5A9E5FAF9F2E9E9FE6EE0E8A3A62715810 --memo 12345 --icp 1.2

dfx canister call nns-ledger transfer '(record { subAccount= "\0b\1a\da\69\60\35\84\1b\e6\d0\71\67\11\04\f6\d7\e2\76\4d\de\96\5f\75\bf\9c\41\83\bb\0d\42\b8\e6" })'  --memo 12345 --icp 1.2 nn

dfx canister call deposits depositIcp

dfx canister call deposits withdrawalsTotal


dfx canister call deposits createWithdrawal '(record {owner=principal "hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe"}, 87_498_125)'

dfx canister call deposits listWithdrawals '(principal "hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe")'

dfx canister call deposits completeWithdrawal '(principal "hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe", 1_399_970_000, principal "a63dq-6k6fh-xc2im-ahqkq-thu3y-ai27f-rgh2u-s5xxy-yohon-te4ur-nqe")'
completeWithdrawal(user: Principal, amount: Nat64, to: Text)


dfx canister --network=ic id deposits

dfx canister call metrics http_request '(record {})'

https://metrics:GdwSHhcZQFZ3AxdJZrTgPBwR@h6uvl-xiaaa-aaaap-qaawa-cai.raw.ic0.app/metrics




dfx canister call deposits metrics --ic
dfx canister call deposits addOwner '(principal "u6b6i-yhv3z-i52d6-w2gny-u2itc-zbwdz-5jnif-con6o-xnj46-w2ow5-kqe")' --ic 



### IMPORTANT 
./scripts/deploy.sh ic upgrade deposits
```

## Journey to address the audit

### 1 Loss of Protocol Funds (StIcp) Due to Inability to Withdraw Remaining Amounts.

Getting the balance of stICP in the `deposits` canister.

```sh
$ dfx canister id deposits --ic
hnwvc-lyaaa-aaaal-aaf6q-cai

$ dfx canister call token balanceOf '(principal "hnwvc-lyaaa-aaaal-aaf6q-cai")' --ic
(5_346_066_490 : nat)
```

Withdraw protocol fees.

```sh
dfx canister call deposits withdrawProtocolFees '(principal "jceob-d4lsq-myex3-3frau-dc5y7-j3cnb-7mawc-4oluq-f24hc-4u56p-5ae")' --ic
```