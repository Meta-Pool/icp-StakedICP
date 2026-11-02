use candid::Principal;
use pocket_ic::PocketIcBuilder;

#[test]
fn pocketic_starts_and_creates_a_canister() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    let canister = pic.create_canister();

    pic.add_cycles(canister, 2_000_000_000_000);

    assert_ne!(canister, Principal::anonymous());
    assert!(pic.cycle_balance(canister) > 0);
}
