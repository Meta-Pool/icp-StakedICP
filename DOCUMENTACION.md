# Documentacion stICP

## Introduccion

Protocolo de staking liquido para Internet Computer (ICP). El protocolo esta compuesto por multiples canisters, los cuales manejan la logica principal del protocolo.

Los canisters son los siguientes, los detalles y los id pueden encontrarse aca, `./canister_ids.json`.

- deposits
- token
- signing
- website
- nns-governance
- nns-ledger
- geoip
- metrics

## Flujo del usuario

El canister **deposits** es el que contiene la logica principal del protocolo, el codigo puede ser encontrado aca, `./src/deposits/deposits.mo`.

Para depositar tokens de `ICP` en el protocolo, es necesario llamar la siguiente funcion para generar una subcuenta entre el canister y el usuario que enviara los fondos.

```motoko
public shared(msg) func getDepositAddress(code: ?Text): async Text;
public shared(msg) func getDepositAddressFor(user: Principal): async Text;

public shared(msg) func getDepositSubaccount(code: ?Text): async Blob;
public shared(msg) func getDepositSubaccountFor(user: Principal): async Blob;
```

Posteriormente, una vez enviados los tokens `ICP` al contrato, es necesario correr la siguiente funcion para que se puedan mintear los stICP tokens.

```motoko
public shared(msg) func depositIcp(): async DepositReceipt;
public shared(msg) func depositIcpFor(user: Principal): async DepositReceipt;
```

Los depositos que entran al canister, antes de ser enviados a las neuronas, se utilizan para cubrir ordenes de retiro pendientes.

```motoko
private func doDepositIcpFor(user: Principal): async DepositReceipt {
    ...

    // Use this to fulfill any pending withdrawals.
    ignore withdrawals.depositIcp(amount.e8s, ?now);

    ...
}
```

Al momento de hacer un deposito, se esta llamando la logica del modulo de withdrawals, el cual puede ser revisado aca, `./src/deposits/Withdrawals.mo`.

Por ultimo, para mintear los nuevos tokens de `stICP` se manda a llamar el modulo de token, que se encuentra aca, `./src/DIP20/motoko/src/token.mo`.

```motoko
let result = await token.icrc1_transfer({
    from_subaccount = ?mintingSubaccount;
    to              = to;
    amount          = Nat64.toNat(amount);
    fee             = null;
    memo            = null;
    created_at_time = ?Nat64.fromNat(Int.abs(Time.now()));
});
```

## Cron Job

El canister require de un cronjob externo que este actualizando valores. La siguiente funcion es llamada a traves del ejecutable de rust que se encuentra aca, `./cmd/oracle/src/main.rs`.

```motoko
public shared(msg) func refreshNeuronsAndApplyInterest(): async [(Nat64, Nat64, Bool)]
```

Posteriormente, el contrato tiene una funcion de **heartbeat** la cual es manejada por ICP.

```motoko
system func heartbeat() : async ()
```