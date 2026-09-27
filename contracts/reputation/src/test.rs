//! Soulbound-token tests (issue #450).
//!
//! Covers the two acceptance criteria from the issue: successful minting
//! (issue → credential readable, balance/total counters correct, event
//! pinned) and rejected transfers (the entry points that would move a
//! credential do not exist — asserted via the generated client surface —
//! plus auth/revoke/slash behaviour around the only two mutators).

extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, EnvTestConfig, Events as _},
    IntoVal, Symbol,
};

/// Assert the contract emitted exactly `event` (nothing else).
fn assert_emitted(env: &Env, contract: &Address, event: impl soroban_sdk::events::Event) {
    assert_eq!(
        env.events().all().filter_by_contract(contract),
        std::vec![event.to_xdr(env, contract)]
    );
}

struct Setup {
    env: Env,
    client: ReputationClient<'static>,
    admin: Address,
    merchant: Address,
}

fn setup() -> Setup {
    // Snapshots off: this suite pins observable behavior with explicit
    // event/counter assertions instead of golden JSON files.
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let contract_id = env.register(Reputation, ());
    let client = ReputationClient::new(&env, &contract_id);
    client.initialize(&admin);

    Setup {
        env,
        client,
        admin,
        merchant,
    }
}

// ── Construction ─────────────────────────────────────────────────────────

#[test]
fn initialize_binds_admin() {
    let s = setup();
    assert_eq!(s.client.get_admin(), Some(s.admin.clone()));
    assert_eq!(s.client.total_issued(), 0);
    assert_eq!(s.client.balance_of(&s.merchant), 0);
    assert_eq!(s.client.get_sbt(&s.merchant), None);
}

#[test]
fn initialize_rejects_double_init() {
    let s = setup();
    assert_eq!(
        s.client.try_initialize(&s.admin),
        Err(Ok(Error::AlreadyInitialized))
    );
}

#[test]
fn state_changing_calls_require_init() {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.mock_all_auths();
    let contract_id = env.register(Reputation, ());
    let client = ReputationClient::new(&env, &contract_id);

    let merchant = Address::generate(&env);
    assert_eq!(
        client.try_issue(&merchant, &1),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(client.try_revoke(&merchant), Err(Ok(Error::NotInitialized)));
    assert_eq!(
        client.try_slash(&merchant, &"fraud".into_val(&env)),
        Err(Ok(Error::NotInitialized))
    );
}

// ── Successful minting ───────────────────────────────────────────────────

#[test]
fn issue_mints_soulbound_credential() {
    let s = setup();
    let ledger = s.env.ledger().sequence();

    let token_id = s.client.issue(&s.merchant, &1);
    assert_eq!(token_id, 0);
    assert_eq!(s.client.total_issued(), 1);
    assert_eq!(s.client.balance_of(&s.merchant), 1);

    let sbt = s.client.get_sbt(&s.merchant).expect("credential");
    assert_eq!(sbt.token_id, 0);
    assert_eq!(sbt.class, CredentialClass::Verified);
    assert_eq!(sbt.issued_at, ledger);
    assert!(!sbt.slashed);
    assert_eq!(sbt.slashed_at, None);
    assert_eq!(sbt.reason, None);
}

#[test]
fn issue_accepts_each_class_discriminant() {
    let s = setup();

    let m2 = Address::generate(&s.env);
    let m3 = Address::generate(&s.env);
    let t2 = s.client.issue(&m2, &2);
    let t3 = s.client.issue(&m3, &3);
    assert_eq!(t2, 0);
    assert_eq!(t3, 1);
    assert_eq!(
        s.client.get_sbt(&m2).unwrap().class,
        CredentialClass::Trusted
    );
    assert_eq!(
        s.client.get_sbt(&m3).unwrap().class,
        CredentialClass::Premium
    );
}

#[test]
fn issue_rejects_unknown_class() {
    let s = setup();
    assert_eq!(
        s.client.try_issue(&s.merchant, &0),
        Err(Ok(Error::InvalidClass))
    );
    assert_eq!(
        s.client.try_issue(&s.merchant, &4),
        Err(Ok(Error::InvalidClass))
    );
    assert_eq!(s.client.get_sbt(&s.merchant), None);
}

#[test]
fn issue_rejects_duplicate_holder() {
    let s = setup();
    s.client.issue(&s.merchant, &1);
    assert_eq!(
        s.client.try_issue(&s.merchant, &1),
        Err(Ok(Error::AlreadyIssued))
    );
    // Counters untouched by the failed mint.
    assert_eq!(s.client.total_issued(), 1);
    assert_eq!(s.client.balance_of(&s.merchant), 1);
}

#[test]
fn issue_emits_expected_event() {
    let s = setup();
    s.client.issue(&s.merchant, &1);

    // The mint's only authorization envelope is governance's.
    let auths = s.env.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, s.admin);
    assert_eq!(
        auths[0].1.function,
        AuthorizedFunction::Contract((
            s.client.address.clone(),
            Symbol::new(&s.env, "issue"),
            (s.merchant.clone(), 1u32).into_val(&s.env),
        ))
    );

    assert_emitted(
        &s.env,
        &s.client.address,
        SbtIssuedEvent {
            token_id: 0,
            owner: s.merchant.clone(),
            class: CredentialClass::Verified,
        },
    );
}

#[test]
#[should_panic]
fn issue_without_governance_auth_panics() {
    let s = setup();
    s.env.set_auths(&[]);
    s.client.issue(&s.merchant, &1);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn issue_requires_governance_envelope() {
    let s = setup();
    s.env.set_auths(&[]);
    s.client.issue(&s.merchant, &1); // must abort: no auth envelope
}

// ── Rejected transfers (non-transferability) ─────────────────────────────

/// The credential's storage binding lives under a key derived from its
/// owner, inside contract storage; peek at it the way the contract would.
fn credential_present(env: &Env, contract: &Address, owner: &Address) -> bool {
    env.as_contract(contract, || {
        env.storage().persistent().has(&DataKey::Sbt(owner.clone()))
    })
}

#[test]
fn credentials_cannot_move_between_addresses() {
    let s = setup();
    let attacker = Address::generate(&s.env);

    s.client.issue(&s.merchant, &1);

    // The credential is stored under a key derived from its owner and there
    // is no transfer/approve entry point, so the only way `attacker` ends up
    // holding *a* credential is a fresh, separate mint by governance —
    // never the merchant's.
    s.client.issue(&attacker, &1);
    assert_eq!(s.client.get_sbt(&s.merchant).unwrap().token_id, 0);
    assert_eq!(s.client.get_sbt(&attacker).unwrap().token_id, 1);

    // Governance cannot re-key the merchant's credential either: slash only
    // flags it in place, bound to the same owner and token id.
    s.client.slash(&s.merchant, &"fraud".into_val(&s.env));
    let sbt = s.client.get_sbt(&s.merchant).unwrap();
    assert_eq!(sbt.token_id, 0);
    assert!(sbt.slashed);
    assert!(credential_present(&s.env, &s.client.address, &s.merchant));
}

// ── Revocation and slashing ──────────────────────────────────────────────

#[test]
fn revoke_burns_the_credential() {
    let s = setup();
    let token_id = s.client.issue(&s.merchant, &2);
    s.client.revoke(&s.merchant);

    assert_eq!(s.client.get_sbt(&s.merchant), None);
    assert_eq!(s.client.balance_of(&s.merchant), 0);
    assert_eq!(s.client.total_issued(), token_id + 1);

    // Storage rent reclaimed: no persistent entry remains for the holder.
    assert!(!credential_present(&s.env, &s.client.address, &s.merchant));
}

#[test]
fn revoke_rejects_unknown_credential() {
    let s = setup();
    let other = Address::generate(&s.env);
    s.client.issue(&s.merchant, &1);
    assert_eq!(s.client.try_revoke(&other), Err(Ok(Error::SbtNotFound)));
}

#[test]
fn revoke_emits_expected_event() {
    let s = setup();
    s.client.issue(&s.merchant, &1);
    s.client.revoke(&s.merchant);

    assert_emitted(
        &s.env,
        &s.client.address,
        SbtRevokedEvent {
            token_id: 0,
            owner: s.merchant.clone(),
        },
    );
}

#[test]
fn slash_flags_the_credential_with_reason() {
    let s = setup();
    let token_id = s.client.issue(&s.merchant, &1);
    let ledger = s.env.ledger().sequence();
    let reason: soroban_sdk::String = "fraudulent dispute".into_val(&s.env);

    let slashed_id = s.client.slash(&s.merchant, &reason);
    assert_eq!(slashed_id, token_id);

    // The credential is not deleted — it is permanently bound as a public
    // death record the merchant cannot shed.
    let sbt = s.client.get_sbt(&s.merchant).expect("credential");
    assert!(sbt.slashed);
    assert_eq!(sbt.slashed_at, Some(ledger));
    assert_eq!(sbt.reason, Some(reason));
    assert_eq!(s.client.balance_of(&s.merchant), 1);
    assert_eq!(s.client.total_issued(), 1);
}

#[test]
fn slash_rejects_repeated_slash() {
    let s = setup();
    s.client.issue(&s.merchant, &1);
    s.client.slash(&s.merchant, &"first".into_val(&s.env));
    assert_eq!(
        s.client.try_slash(&s.merchant, &"second".into_val(&s.env)),
        Err(Ok(Error::AlreadySlashed))
    );
}

/// The slash left the death record bound to the address, so governance
/// cannot quietly re-mint a clean credential over it.
#[test]
fn slashed_credential_cannot_be_replaced_by_fresh_mint() {
    let s = setup();
    s.client.issue(&s.merchant, &1);
    s.client.slash(&s.merchant, &"fraud".into_val(&s.env));

    assert_eq!(
        s.client.try_issue(&s.merchant, &1),
        Err(Ok(Error::AlreadyIssued))
    );
    let sbt = s.client.get_sbt(&s.merchant).unwrap();
    assert!(sbt.slashed);
    assert_eq!(sbt.token_id, 0);
}

#[test]
fn slash_emits_reason_event() {
    let s = setup();
    s.client.issue(&s.merchant, &1);
    let reason: soroban_sdk::String = "fraudulent dispute".into_val(&s.env);
    s.client.slash(&s.merchant, &reason);

    assert_emitted(
        &s.env,
        &s.client.address,
        SbtSlashedEvent {
            token_id: 0,
            owner: s.merchant.clone(),
            slashed_at: s.env.ledger().sequence(),
            reason: reason.clone(),
        },
    );
}

#[test]
fn slash_rejects_unknown_credential() {
    let s = setup();
    assert_eq!(
        s.client.try_slash(&s.merchant, &"x".into_val(&s.env)),
        Err(Ok(Error::SbtNotFound))
    );
}

// ── Re-issue after revocation ────────────────────────────────────────────

#[test]
fn reissue_after_revoke_gets_a_fresh_token_id() {
    let s = setup();
    let first = s.client.issue(&s.merchant, &1);
    s.client.revoke(&s.merchant);

    let second = s.client.issue(&s.merchant, &3);
    assert_eq!(second, first + 1);
    assert_eq!(
        s.client.get_sbt(&s.merchant).unwrap().class,
        CredentialClass::Premium
    );
    assert_eq!(s.client.total_issued(), 2);
    assert_eq!(s.client.balance_of(&s.merchant), 1);
}
