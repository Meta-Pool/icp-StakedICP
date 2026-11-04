use candid::{decode_one, encode_one, Principal};
use pocket_ic::PocketIcBuilder;
use recovery_canister::types::ConfigView;

const DEPOSITS: &str = "hnwvc-lyaaa-aaaal-aaf6q-cai";
const LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
const OWNER: &str = "pjxyk-lcswf-tle2g-npj6z-mkxdc-h5dzs-qeirn-5fa3o-kayp4-gyvax-mqe";
const DESTINATION: &str = "nudnk-xwpjb-buxs6-bkfa3-icpfm-n7kwk-q7kqf-fhvcm-cl564-ezl7h-kae";

use candid::{CandidType, Nat};
use ic_ledger_types::{AccountIdentifier, DEFAULT_SUBACCOUNT};
use recovery_canister::types::{TransferOk, TransferRequest};
use serde::Deserialize;

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Tokens {
    e8s: u64,
}

#[derive(CandidType, Deserialize)]
struct LedgerInit {
    minting_account: String,
    icrc1_minting_account: Option<LedgerAccount>,
    initial_values: Vec<(String, Tokens)>,
    max_message_size_bytes: Option<u64>,
    transaction_window: Option<LedgerDuration>,
    archive_options: Option<ArchiveOptions>,
    send_whitelist: Vec<Principal>,
    transfer_fee: Option<Tokens>,
    token_symbol: Option<String>,
    token_name: Option<String>,
    feature_flags: Option<FeatureFlags>,
    maximum_number_of_accounts: Option<u64>,
    accounts_overflow_trim_quantity: Option<u64>,
}

#[derive(CandidType, Deserialize)]
struct LedgerAccount {
    owner: Principal,
    subaccount: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize)]
struct LedgerDuration {
    secs: u64,
    nanos: u32,
}

#[derive(CandidType, Deserialize)]
struct ArchiveOptions {
    trigger_threshold: u64,
    num_blocks_to_archive: u64,
    node_max_memory_size_bytes: Option<u64>,
    max_message_size_bytes: Option<u64>,
    controller_id: Principal,
    cycles_for_archive_creation: Option<u64>,
}

#[derive(CandidType, Deserialize)]
struct FeatureFlags {
    icrc2: bool,
}

#[derive(CandidType, Deserialize)]
enum LedgerPayload {
    Init(LedgerInit),
    Upgrade(Option<()>),
}

#[test]
fn recovery_wasm_installs_with_production_identity() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let source = Principal::from_text(DEPOSITS).unwrap();
    let owner = Principal::from_text(OWNER).unwrap();

    // Create a LOCAL canister using the production ID.
    let created = pic
        .create_canister_with_id(Some(owner), None, source)
        .expect("Cannot create deposits locally");

    assert_eq!(created, source);

    // Fund the LOCAL recovery canister with 4 trillion cycles.
    pic.add_cycles(source, 4_000_000_000_000);

    let wasm = std::fs::read("target/wasm32-unknown-unknown/release/recovery_canister.wasm")
        .expect("Recovery Wasm missing");

    pic.install_canister(source, wasm, encode_one(()).unwrap(), Some(owner));

    let reply = pic
        .query_call(source, owner, "get_config", encode_one(()).unwrap())
        .expect("get_config failed");

    let config: ConfigView = decode_one(&reply).unwrap();

    assert_eq!(config.source_canister, source);
    assert_eq!(config.authorized_caller, owner);
    assert_eq!(
        config.destination,
        Principal::from_text(DESTINATION).unwrap()
    );
    assert_eq!(config.ledger, Principal::from_text(LEDGER).unwrap());
    assert_eq!(config.fee_e8s, 10_000);

    println!("Recovery Wasm installed successfully.");
    println!("Source: {}", config.source_canister);
    println!("Destination: {}", config.destination);
    println!("Authorized caller: {}", config.authorized_caller);
}

#[test]
fn recovery_transfers_icp_exactly_once() {
    const SOURCE_BALANCE: u64 = 94_233_666_604;
    const DEST_BALANCE: u64 = 50_000_000;
    const AMOUNT: u64 = 10_000_000;
    const FEE: u64 = 10_000;

    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let source = Principal::from_text(DEPOSITS).unwrap();
    let ledger = Principal::from_text(LEDGER).unwrap();
    let owner = Principal::from_text(OWNER).unwrap();
    let destination = Principal::from_text(DESTINATION).unwrap();

    let source_account = AccountIdentifier::new(&source, &DEFAULT_SUBACCOUNT).to_hex();
    let destination_account = AccountIdentifier::new(&destination, &DEFAULT_SUBACCOUNT).to_hex();

    // Confirm we are simulating the exact production accounts.
    assert_eq!(
        source_account,
        "0c5e0de7c8b95004dc3ebe8104611441ac59dc8eb02494e46e616305621e32ed"
    );
    assert_eq!(
        destination_account,
        "2c4f810252eef78e5e81f15a086bc7b1fc5706bacbfa13fdf4e6c1fd9ae3ac26"
    );

    // A separate minting account, never our source or destination.
    let minting_account =
        AccountIdentifier::new(&Principal::anonymous(), &DEFAULT_SUBACCOUNT).to_hex();

    // 1. Create the LOCAL ICP Ledger with its production canister ID.
    pic.create_canister_with_id(Some(owner), None, ledger)
        .expect("Cannot create local Ledger");
    pic.add_cycles(ledger, 4_000_000_000_000);

    let init = LedgerPayload::Init(LedgerInit {
        minting_account,
        icrc1_minting_account: None,
        initial_values: vec![
            (
                source_account,
                Tokens {
                    e8s: SOURCE_BALANCE,
                },
            ),
            (destination_account, Tokens { e8s: DEST_BALANCE }),
        ],
        max_message_size_bytes: None,
        transaction_window: None,
        archive_options: None,
        send_whitelist: vec![],
        transfer_fee: Some(Tokens { e8s: FEE }),
        token_symbol: Some("ICP".to_string()),
        token_name: Some("Internet Computer".to_string()),
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    });

    // Decompress the official Ledger artifact locally.
    let output = std::process::Command::new("gzip")
        .args(["-dc", "tests/fixtures/ledger-canister.wasm.gz"])
        .output()
        .expect("gzip unavailable");

    assert!(output.status.success(), "Ledger decompression failed");

    pic.install_canister(
        ledger,
        output.stdout,
        encode_one(init).unwrap(),
        Some(owner),
    );

    // 2. Install the actual recovery Wasm.
    pic.create_canister_with_id(Some(owner), None, source)
        .expect("Cannot create local deposits");
    pic.add_cycles(source, 4_000_000_000_000);

    let wasm =
        std::fs::read("target/wasm32-unknown-unknown/release/recovery_canister.wasm").unwrap();

    pic.install_canister(source, wasm, encode_one(()).unwrap(), Some(owner));

    // Helper for reading actual ICRC-1 balances.
    let balance = |principal: Principal| -> u64 {
        let account = icrc_ledger_types::icrc1::account::Account {
            owner: principal,
            subaccount: None,
        };

        let response = pic
            .query_call(
                ledger,
                owner,
                "icrc1_balance_of",
                encode_one(account).unwrap(),
            )
            .expect("Ledger balance query failed");

        let amount: Nat = decode_one(&response).unwrap();
        u64::try_from(amount.0).unwrap()
    };

    assert_eq!(balance(source), SOURCE_BALANCE);
    assert_eq!(balance(destination), DEST_BALANCE);

    // 3. Transfer 0.1 fictitious ICP.
    let request = TransferRequest {
        expected_operation_id: 1,
        amount_e8s: AMOUNT,
        expected_fee_e8s: FEE,
        manifest_tag: vec![7; 16],
    };

    let response = pic
        .update_call(
            source,
            owner,
            "transfer",
            encode_one(request.clone()).unwrap(),
        )
        .expect("Recovery transfer rejected");

    let result: Result<TransferOk, recovery_canister::types::RecoveryError> =
        decode_one(&response).unwrap();

    let transfer = result.expect("Ledger transfer failed");
    println!("Transfer confirmed in block {}", transfer.block_index);

    assert_eq!(balance(source), SOURCE_BALANCE - AMOUNT - FEE);
    assert_eq!(balance(destination), DEST_BALANCE + AMOUNT);

    // 4. Replay the same request.
    let replay = pic
        .update_call(source, owner, "transfer", encode_one(request).unwrap())
        .expect("Replay call rejected");

    let replay_result: Result<TransferOk, recovery_canister::types::RecoveryError> =
        decode_one(&replay).unwrap();

    assert!(replay_result.is_err());

    // The destination must NOT receive another 0.1 ICP.
    assert_eq!(balance(source), SOURCE_BALANCE - AMOUNT - FEE);
    assert_eq!(balance(destination), DEST_BALANCE + AMOUNT);

    println!("PASS: 0.1 ICP transferred exactly once.");
}
