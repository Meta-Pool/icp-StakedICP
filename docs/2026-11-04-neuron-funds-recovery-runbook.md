# Instructivo: recuperar los fondos de las neuronas en disolución

**Escrito:** 2026-11-04 · **Para ejecutar:** entre 2027-04 y 2028-10 (según el calendario)
**Herramienta:** [`tools/neuron-audit`](../tools/neuron-audit/README.md) (Rust) · **Contexto previo:** [2026-11-02-deposits-icp-recovery.md](./2026-11-02-deposits-icp-recovery.md) (el ICP líquido de `deposits` ya se recuperó)

> Este documento asume que quien lo lee no recuerda nada del proyecto. Ve despacio, no te saltes pasos,
> y **detente ante cualquier línea `BLOCKED`, `Discrepancy` o resultado inesperado**.

## 1. Qué se hace (resumen)

Las neuronas del NNS controladas por el viejo Oracle de stICP ya están disolviéndose. Cuando una llega a
su fecha, queda en estado `DISSOLVED` (state = 3) y sus ICP se pueden retirar. Es **un solo movimiento**:

- **`recover-disburse`** (Governance `Disburse`): la neurona disuelta envía su stake **directamente** a la
  wallet destino que indiques con `--destination`. La herramienta **no tiene destino por defecto**: sin
  `--destination` no corre. El canister `deposits` ya **no interviene** (está deprecado).

Datos fijos:

| Qué | Valor |
|---|---|
| Governance | `rrkah-fqaaa-aaaaa-aaaaq-cai` |
| ICP Ledger | `ryjl3-tyaaa-aaaaa-aaaba-cai` |
| Canister de firma (controla las neuronas vía Oracle) | `onfif-zaaaa-aaaar-qaama-cai` |
| Owners del canister de firma (2026-11-04) | `sticpowner`: `pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe`; Meta Pool: `nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae` |
| Destinatario (Meta Pool), valor de `--destination` | `nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae` |
| Cuenta ICP del destinatario (se espera ver esta en el payload) | `2c4f810252eef78e5e81f15a086bc7b1fc5706bacbfa13fdf4e6c1fd9ae3ac26` |
| Fee del Ledger | 10 000 e8s (0.0001 ICP) |

> Antes de mover nada, confirma con Meta Pool que el destinatario sigue siendo el mismo.
> Verifica la cuenta: `dfx ledger account-id --of-principal <principal>` debe dar la cuenta de la tabla.

## 2. Calendario de disolución

Generado el 2026-10-27 22:31:43 UTC (consulta on-chain anónima `get_neuron_info`).
Fecha de disolución = `retrieved_at_timestamp_seconds + dissolve_delay_seconds` (state = 2).

| # | Neuron ID | Stake (ICP) | Se disuelve el (UTC) | Días restantes (al 2026-10-27) |
|---|---|---|---|---|
| 1 | 17664423740665568815 | 551.71279809 | 2027-04-28 13:22:53 | 182 |
| 2 | 9271963002738860297 | 552.75949769 | 2027-10-28 04:18:50 | 365 |
| 3 | 6123790069568146470 | 549.90666805 | 2028-04-27 19:17:28 | 547 |
| 4 | 436472328193651593 | 511.97356573 | 2028-10-27 09:57:53 | 730 |
| 5 | 1479873936384536384 | 513.68334179 | 2028-10-27 10:15:02 | 730 |
| 6 | 3412769759387581069 | 523.83391012 | 2028-10-27 10:15:39 | 730 |
| 7 | 3874491508480854881 | 518.78420133 | 2028-10-27 10:16:10 | 730 |
| 8 | 4198032462564105614 | 527.17446873 | 2028-10-27 10:16:47 | 730 |
| 9 | 7287727394075407820 | 520.47127052 | 2028-10-27 10:17:54 | 730 |
| 10 | 8456643092464934519 | 517.08558287 | 2028-10-27 10:18:23 | 730 |
| 11 | 9825007284316578685 | 522.15460666 | 2028-10-27 10:19:21 | 730 |
| 12 | 10497993268409709965 | 528.83596761 | 2028-10-27 10:19:49 | 730 |
| 13 | 14413539606994202212 | 532.14579209 | 2028-10-27 10:20:23 | 730 |
| 14 | 14430744586422539576 | 515.38636622 | 2028-10-27 10:20:59 | 730 |
| 15 | 14724800492480835604 | 530.49343200 | 2028-10-27 10:21:27 | 730 |
| 16 | 15059966891614805967 | 525.50562927 | 2028-10-27 10:22:13 | 730 |

**Total: 16 neuronas, 8441.90709877 ICP.**

Fuera de esta tabla (al 2026-10-27): 16 neuronas bloqueadas (state 1, no disolviéndose), 26 ya disueltas
(state 3), 0 en otro estado, 0 errores de consulta. Las 26 ya disueltas y las 16 bloqueadas **no** están
cubiertas por este calendario: revisa el estado actual (paso 4) y el
[README de la herramienta](../tools/neuron-audit/README.md).

Para regenerar la tabla con datos actuales (solo lectura, no firma nada):

```sh
tools/neuron-audit/scripts/dissolving-report.sh   # escribe tools/neuron-audit/audit-out/dissolving-neurons.md
```

## 3. Preparación (una sola vez)

### 3.1 Requisitos

- Repositorio clonado (`icp-StakedICP`) en la rama/commit donde vive `tools/neuron-audit`. Si dudas, usa el
  último commit de `main` y revisa que `tools/neuron-audit/Cargo.toml` exista.
- Rust ≥ 1.85 (`rustup update stable`; `cargo --version`).
- `dfx` instalado (`dfx --version`) — se usa para consultas y para exportar la llave.
- Acceso a la llave de `sticpowner` (ver 3.3). **Sin esa llave no se puede firmar nada.**

### 3.2 Compilar `tools/`

Desde la raíz del repositorio:

```sh
cd tools/neuron-audit
cargo build --release
cargo test            # debe pasar; si falla, no continúes
cd ../..
```

(Los comandos de abajo usan `cargo run --manifest-path tools/neuron-audit/Cargo.toml -- …`, que compila
automáticamente; la compilación explícita solo sirve para detectar problemas temprano.)

Si Cargo.lock ya no resuelve (crates retiradas, Rust muy nuevo), compila con `--locked` en una toolchain
de la época o actualiza dependencias y vuelve a correr `cargo test`.

No hace falta compilar ni instalar el canister de recuperación (`recovery-canister/`): ya no se usa.

### 3.3 Obtener una llave válida

Solo puede firmar un **owner** del canister de firma (`sign` exige `require_owner`). Consulta la lista vigente
(solo lectura):

```sh
dfx canister --network ic --identity anonymous call onfif-zaaaa-aaaar-qaama-cai get_all_owners --query \
  --candid src/signing/signing.did
```

Al 2026-11-04 devolvía **dos owners**: `sticpowner` (`pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe`)
y Meta Pool (`nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae`). Cualquier principal de esa
lista puede firmar; si hoy hay otros, úsalos.

#### Quién puede ejecutar `recover-disburse`

Puede ejecutarlo cualquier owner que tenga su llave como PEM (secp256k1 o ed25519). Hoy son:

| Quién | Principal | Estado |
|---|---|---|
| `sticpowner` | `pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe` | Owner (verificado on-chain 2026-11-04) |
| Wallet de Meta Pool | `nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae` | Owner (verificado on-chain 2026-11-04): puede ejecutarlo |

Meta Pool se agregó el 2026-11-04 con (referencia; **no repetir**, `add_owner` no deduplica):

```sh
dfx canister --network ic --identity sticpowner call onfif-zaaaa-aaaar-qaama-cai add_owner \
  '(principal "nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae")'
```

Cuando Meta Pool ejecute, usa su propio PEM y su principal (el valor por defecto de `--owner-principal` es
el de `sticpowner`):

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- recover-disburse \
  --neuron-id <NEURON_ID> --amount-e8s <STAKE_E8S - 10000> \
  --destination nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae \
  --owner-principal nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae \
  --owner-pem <RUTA_AL_PEM_DE_META_POOL>
```

(Agrega `--execute --approve-payload-sha256 <HASH>` solo tras revisar el modo preparar, igual que en la
sección 5.) El preflight aborta si el PEM no corresponde a `--owner-principal` o si ese principal no está en
`get_all_owners`. Un owner firma con la llave del Oracle, que controla las neuronas: es control total sobre
ellas, no solo permiso para `recover-disburse`.

Los **controladores** del canister (cambian el código, pero no firman por sí mismos) eran, al 2026-11-04:
`3edrk-3t6nh-oirx2-62e6a-aifra-2xmat-vd243-yrqau-yjppw-pwybw-rae`,
`c2zqk-zh4xf-waqzz-hhd74-mumvp-nboec-nb7qo-atlpk-jpse7-vg6ho-2ae`,
`gok3t-phhkg-xcypi-hlnoo-4eqma-bb4cx-zaawz-pbdib-fdg63-ocac5-4ae`,
`j22eq-rygta-dltz2-jvmgw-fnlpj-6b4ss-rw3eb-xasgf-k6z4m-y4htu-zqe`,
`nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae` (Meta Pool),
`pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe`,
`u6b6i-yhv3z-i52d6-w2gny-u2itc-zbwdz-5jnif-con6o-xnj46-w2ow5-kqe`,
`whhnj-fwgiz-zmesc-6kjkk-anvcb-wyyb6-eqicm-ztlw3-awnis-di4ni-tqe`,
`zhfn3-haobh-mejz2-otnmz-sa6wp-6ya5h-qatef-zy2i4-ec736-7jqu5-pqe`
(`dfx canister --network ic info onfif-zaaaa-aaaar-qaama-cai`).

Si todos los owners pierden su llave, no se puede agregar otro (`add_owner` también exige ser owner). La salida es que los controladores actualicen el canister (upgrade con un `InitArgs`/estado
que incluya un nuevo owner) y luego firmar con esa nueva llave. Hazlo con tiempo, mucho antes de 2027-04.

La identidad `sticpowner` estaba en el **Keychain de macOS**, no en `~/.config/dfx/identity/`. Se exporta así:

```sh
mkdir -p ~/.icp-recovery-private && chmod 700 ~/.icp-recovery-private
dfx identity export sticpowner > ~/.icp-recovery-private/sticpowner.pem
chmod 600 ~/.icp-recovery-private/sticpowner.pem
dfx identity get-principal --identity sticpowner   # debe imprimir un principal de get_all_owners
```

Si firmas con un owner distinto de `sticpowner`, agrega `--owner-principal <TU_PRINCIPAL>` a
`recover-disburse` (por defecto la herramienta espera el principal de `sticpowner` y el preflight fallaría).

Nunca subas el `.pem` al repositorio ni lo pegues en chats; bórralo al terminar.

## 4. Verificar qué neuronas están listas

1. Ejecuta el reporte de solo lectura (sección 2) y ve cuáles aparecen ya como `dissolved` (state 3), o
   consulta una en concreto:

   ```sh
   dfx canister call --network ic --identity anonymous --query \
     --candid candid/nns-governance.did rrkah-fqaaa-aaaaa-aaaaq-cai \
     get_neuron_info '(<NEURON_ID> : nat64)'
   ```

   `state = 3` ⇒ disuelta. `state = 2` ⇒ aún disolviéndose, espera a su fecha.
2. Solo procede con neuronas en `state = 3`. Anota ID y `stake_e8s`.

## 5. Procedimiento, una neurona a la vez

Todos los comandos se corren desde la **raíz del repositorio**. Usa `PEM=~/.icp-recovery-private/sticpowner.pem`.

### 5.1 Disburse: preparar (no firma ni envía nada)

`amount-e8s` = stake de la neurona **menos 10 000** (el fee se cobra aparte, encima del monto, y la
herramienta exige `stake ≥ amount + fee`).

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- recover-disburse \
  --neuron-id <NEURON_ID> --amount-e8s <STAKE_E8S - 10000> \
  --destination nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae
```

Revisa lo impreso: neurona, estado `DISSOLVED`, monto y que **`Destination` sea exactamente**
`2c4f810252eef78e5e81f15a086bc7b1fc5706bacbfa13fdf4e6c1fd9ae3ac26`. Un disburse a una cuenta equivocada es
irreversible. Si aparece `WARNING … holds 0 ICP`, confirma con Meta Pool que es normal. Copia el
`payload sha256` que imprime.

### 5.2 Disburse: ejecutar

Solo si todo lo anterior es correcto (mismos argumentos, más estos tres):

```sh
cargo run --manifest-path tools/neuron-audit/Cargo.toml -- recover-disburse \
  --neuron-id <NEURON_ID> --amount-e8s <STAKE_E8S - 10000> \
  --destination nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae \
  --owner-pem $PEM --execute --approve-payload-sha256 <HASH_DEL_PASO_5.1>
```

La herramienta firma ese único payload, lo envía y verifica el bloque del Ledger (monto exacto y
destinatario = `--destination`). Debe terminar con veredicto de éxito y `MATCH`.

- **No reintentes** si hay timeout o error ambiguo. Primero revisa `audit-out/recovery/` (journal/resultado)
  y el balance del destino; no repitas hasta confirmar que no se envió.
- Repite 5.1–5.2 para cada neurona disuelta, una por una.

### 5.3 Verificación final

- Confirma con Meta Pool que recibió cada monto; verifica el bloque en el dashboard del Ledger.
- Conserva `audit-out/recovery/` como evidencia.

## 6. Reglas de oro

- Una neurona y una operación a la vez; nunca borres ni edites archivos de `audit-out/**/journal/`.
- `--execute` solo después de leer el resultado del paso de preparación.
- Conserva `audit-out/` (planes, journals, manifiestos, reconciliaciones) como registro y haz commit.
- Si la herramienta ya no compila o el canister de firma/Governance cambió de interfaz, no improvises:
  detente y busca apoyo técnico.
- Al terminar: borra `~/.icp-recovery-private/sticpowner.pem`.

## 7. Registro de ejecución (llenar al operar)

| Neurona | Fecha disburse | Monto (e8s) | Bloque Ledger | Confirmado por Meta Pool |
|---|---|---|---|---|
| | | | | |
