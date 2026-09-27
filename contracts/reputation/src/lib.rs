//! On-chain reputation for Accensa (issue #450).
//!
//! This contract is the protocol's identity layer: it records, in
//! non-transferable form, that a merchant has been vetted by governance. A
//! soulbound token (SBT) minted here is permanently bound to one address —
//! there is no transfer, approval or market path — so a verified-merchant
//! badge can never be bought, borrowed or farmed. Its whole value is that it
//! is worth nothing to anyone but the holder.
//!
//! # Access model
//!
//! - `issue` / `revoke` / `slash` are restricted to the **governance** admin
//!   bound at construction (the multisig or `Governance` contract address).
//! - Everything else is read-only, so indexers and the bazaar discovery
//!   registry can gate on verification without paying for auth.
//!
//! # Storage shape
//!
//! - `Sbt(Address)` — persistent, one entry per credential: owner, class,
//!   issue/slash metadata and a monotonically increasing token id. The
//!   `owner` in the entry is redundant with the storage key on purpose: it
//!   keeps the credential self-describing for off-chain indexers reading the
//!   WASM spec.
//! - `Balance(Address)` — persistent counter kept alongside the credentials
//!   so `balance_of` is one entry read instead of a full-key iteration.
//!
//! Revocation deletes the credential entry (and decrements the balance)
//! rather than flagging it, so a slashed merchant's storage rent is
//! reclaimed immediately.
//!
//! # Non-transferability by construction
//!
//! Only `issue` and `revoke` change credential ownership, and both are
//! admin-gated. There is intentionally no `transfer`, `approve`,
//! `transfer_from` or `spendable_*` entry point (issue #450), so no caller
//! — not even the admin — can move a credential between addresses.

#![no_std]

pub mod sbt;

use sbt::{CredentialClass, SoulboundToken};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype, Address, Env,
};

contractmeta!(key = "name", val = "AccensaReputation");
contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(
    key = "repo",
    val = "https://github.com/accensa/accensa-contracts"
);

/// Errors are local to this contract rather than added to
/// `accensa_common::Error`: every contract that exposes the shared enum
/// embeds all of its variants in its WASM spec, so growing it would enlarge
/// unrelated contracts.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// `initialize` was called after the contract was already initialized.
    AlreadyInitialized = 1,
    /// A state-changing call was made before `initialize`.
    NotInitialized = 2,
    /// The caller is not the governance admin.
    Unauthorized = 3,
    /// The merchant already holds a soulbound credential.
    AlreadyIssued = 4,
    /// No soulbound credential exists for this address.
    SbtNotFound = 5,
    /// The credential class is not a valid [`CredentialClass`] value.
    InvalidClass = 6,
    /// The credential is already slashed.
    AlreadySlashed = 7,
}

#[contracttype]
pub enum DataKey {
    /// Instance: the governance address that issues and revokes credentials.
    Admin,
    /// Instance: number of credentials ever minted; also the next token id.
    SbtCount,
    /// Persistent, one entry per soulbound credential, keyed by owner.
    Sbt(Address),
    /// Persistent, one entry per holder: live credentials they own.
    Balance(Address),
}

/// Emitted when a soulbound credential is minted to a merchant.
///
/// Topics: `("sbt_issued", token_id, owner)`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbtIssuedEvent {
    #[topic]
    pub token_id: u64,
    #[topic]
    pub owner: Address,
    pub class: CredentialClass,
}

/// Emitted when a soulbound credential is burned (unslashed) by governance.
///
/// Topics: `("sbt_revoked", token_id, owner)`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbtRevokedEvent {
    #[topic]
    pub token_id: u64,
    #[topic]
    pub owner: Address,
}

/// Emitted when a soulbound credential is slashed by governance. The
/// credential stays bound to its holder as a public death record — it is
/// flagged, not deleted, so a slashed merchant cannot re-mint a clean one.
///
/// Topics: `("sbt_slashed", token_id, owner)`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbtSlashedEvent {
    #[topic]
    pub token_id: u64,
    #[topic]
    pub owner: Address,
    pub slashed_at: u32,
    pub reason: soroban_sdk::String,
}

/// Checks-effects-interactions helper: persist the credential and its
/// holder's balance counter, keeping both live for the shared ~30-day policy.
fn store(env: &Env, owner: &Address, sbt: &SoulboundToken) {
    let key = DataKey::Sbt(owner.clone());
    env.storage().persistent().set(&key, sbt);
    env.storage().persistent().extend_ttl(&key, 100, 518_400);

    let balance_key = DataKey::Balance(owner.clone());
    let balance: u64 = env.storage().persistent().get(&balance_key).unwrap_or(0);
    env.storage()
        .persistent()
        .set(&balance_key, &balance.saturating_add(1));
    env.storage()
        .persistent()
        .extend_ttl(&balance_key, 100, 518_400);
}

#[contract]
pub struct Reputation;

#[contractimpl]
impl Reputation {
    /// Bind this instance to `admin` — the governance address (multisig or
    /// `Governance` contract) that alone may issue, revoke or slash
    /// credentials.
    ///
    /// # Errors
    /// - `AlreadyInitialized`: called twice.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::SbtCount, &0u64);
        Ok(())
    }

    /// Mint a non-transferable soulbound credential of `class` to `merchant`.
    /// Governance only. Returns the new token id.
    ///
    /// # Errors
    /// - `NotInitialized`: before `initialize`.
    /// - `Unauthorized`: caller is not the governance admin.
    /// - `AlreadyIssued`: the merchant already holds a credential — including
    ///   a slashed one, which is permanently bound as a public record.
    /// - `InvalidClass`: `class` is not a valid [`CredentialClass`].
    pub fn issue(env: Env, merchant: Address, class: u32) -> Result<u64, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::Sbt(merchant.clone()))
        {
            return Err(Error::AlreadyIssued);
        }
        let class = CredentialClass::from_repr(class).ok_or(Error::InvalidClass)?;

        let token_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::SbtCount)
            .unwrap_or(0);
        let next_id = token_id + 1;
        env.storage().instance().set(&DataKey::SbtCount, &next_id);

        store(
            &env,
            &merchant,
            &SoulboundToken {
                token_id,
                class,
                issued_at: env.ledger().sequence(),
                slashed: false,
                slashed_at: None,
                reason: None,
            },
        );

        SbtIssuedEvent {
            token_id,
            owner: merchant,
            class,
        }
        .publish(&env);

        Ok(token_id)
    }
    /// Revoke (burn) `merchant`'s soulbound credential. Governance only.
    ///
    /// Revocation is the plain removal path: the credential is deleted and
    /// the holder's balance drops to zero, reclaiming its storage rent. Use
    /// [`Self::slash`] for a punitive adjudication that leaves a permanent,
    /// public death record bound to the address.
    ///
    /// # Errors
    /// - `NotInitialized`: before `initialize`.
    /// - `Unauthorized`: caller is not the governance admin.
    /// - `SbtNotFound`: no credential for this address.
    pub fn revoke(env: Env, merchant: Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Sbt(merchant.clone());
        let sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::SbtNotFound)?;
        env.storage().persistent().remove(&key);

        let balance_key = DataKey::Balance(merchant.clone());
        let balance: u64 = env.storage().persistent().get(&balance_key).unwrap_or(1);
        if balance <= 1 {
            env.storage().persistent().remove(&balance_key);
        } else {
            env.storage().persistent().set(&balance_key, &(balance - 1));
        }

        SbtRevokedEvent {
            token_id: sbt.token_id,
            owner: merchant,
        }
        .publish(&env);

        Ok(())
    }
    /// Slash `merchant`'s soulbound credential with a public `reason`.
    /// Governance only. Returns the slashed credential's token id.
    ///
    /// A slash is the punitive path: the credential is **not** deleted — it
    /// stays permanently bound to the address, flagged with the ledger and
    /// reason of the adjudication — so a slashed merchant cannot simply re-
    /// apply for a clean one ([`Self::issue`] still rejects the duplicate).
    /// Reputation consumers must treat a slashed credential as dead. Use
    /// [`Self::revoke`] for a plain burn with no public record.
    ///
    /// # Errors
    /// - `NotInitialized`: before `initialize`.
    /// - `Unauthorized`: caller is not the governance admin.
    /// - `SbtNotFound`: no credential for this address.
    /// - `AlreadySlashed`: the credential is already slashed.
    pub fn slash(env: Env, merchant: Address, reason: soroban_sdk::String) -> Result<u64, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Sbt(merchant.clone());
        let mut sbt: SoulboundToken = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::SbtNotFound)?;
        if sbt.slashed {
            return Err(Error::AlreadySlashed);
        }

        let slashed_at = env.ledger().sequence();
        sbt.slashed = true;
        sbt.slashed_at = Some(slashed_at);
        sbt.reason = Some(reason.clone());
        env.storage().persistent().set(&key, &sbt);
        env.storage().persistent().extend_ttl(&key, 100, 518_400);

        SbtSlashedEvent {
            token_id: sbt.token_id,
            owner: merchant,
            slashed_at,
            reason,
        }
        .publish(&env);

        Ok(sbt.token_id)
    }

    /// The credential held by `merchant`, or `None` if it holds none.
    pub fn get_sbt(env: Env, merchant: Address) -> Option<SoulboundToken> {
        env.storage().persistent().get(&DataKey::Sbt(merchant))
    }

    /// Number of live credentials `merchant` holds (0 or 1 — a soulbound
    /// token cannot be duplicated per address).
    pub fn balance_of(env: Env, merchant: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(merchant))
            .unwrap_or(0)
    }

    /// Number of credentials ever minted (including revoked ones).
    pub fn total_issued(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::SbtCount)
            .unwrap_or(0)
    }

    /// The governance admin bound at construction, if any.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }
}

#[cfg(test)]
mod test;
