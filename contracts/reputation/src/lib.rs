//! On-chain reputation for Accensa (issue #451).
//!
//! This contract rewards decentralized arbitrators with tiered NFT badges
//! based on their lifetime record of **accurate dispute resolutions** — see
//! [`badges`] for the tier table, minting model and storage shape.
//!
//! # Access model
//!
//! - `initialize` binds a single **arbiter authority** (the dispute-resolution
//!   contract or governance multisig). Only that address may call
//!   `record_resolution`.
//! - Everything else is read-only, so indexers and bazaar listings can gate on
//!   badge tier without paying for auth.
//!
//! # MVP cuts (issue #451)
//!
//! Deliberately out of scope: transfer/approval paths (badges are
//! non-transferable by construction), per-dispute inaccuracy tracking, badge
//! revocation/slashing, and metadata URIs.

#![no_std]

mod badges;
#[cfg(test)]
mod badges_test;

use badges::{Badge, BadgeTier, Error};
use soroban_sdk::{contract, contractimpl, contractmeta, Address, Env};

pub use badges::{
    BadgeMintedEvent, BadgeUpgradedEvent, DataKey as BadgeDataKey, ResolutionRecordedEvent,
    BRONZE_THRESHOLD, GOLD_THRESHOLD, SILVER_THRESHOLD,
};

contractmeta!(key = "name", val = "AccensaReputation");
contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(
    key = "repo",
    val = "https://github.com/accensa/accensa-contracts"
);

#[contract]
pub struct Reputation;

#[contractimpl]
impl Reputation {
    /// Bind this instance to `admin` — the arbiter authority (dispute
    /// resolution contract or governance multisig) that alone may record
    /// resolutions and thereby mint or upgrade badges.
    ///
    /// # Errors
    /// - `AlreadyInitialized`: called twice.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&BadgeDataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&BadgeDataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&BadgeDataKey::BadgeCount, &0u64);
        Ok(())
    }

    /// Record an **accurate** dispute resolution by `arbitrator`, minting
    /// their Bronze badge on the first accepted resolution and upgrading the
    /// badge's tier in place when a lifetime threshold is crossed. Admin
    /// (arbiter authority) only.
    ///
    /// `dispute_id` is ledger-scoped replay protection supplied by the
    /// caller; recording the same id twice is rejected.
    ///
    /// Returns the arbitrator's post-call lifetime accurate count.
    ///
    /// # Errors
    /// - `NotInitialized`: before `initialize`.
    /// - `Unauthorized`: caller is not the arbiter authority.
    /// - `DisputeAlreadyRecorded`: `dispute_id` was already consumed.
    /// - `InaccurateOutcome`: `accurate` is `false` — a badge only tracks
    ///   accurate resolutions.
    pub fn record_resolution(
        env: Env,
        arbitrator: Address,
        dispute_id: u64,
        accurate: bool,
    ) -> Result<u64, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&BadgeDataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        if !accurate {
            return Err(Error::InaccurateOutcome);
        }

        let dispute_key = BadgeDataKey::ResolutionDispute(dispute_id);
        if env.storage().persistent().has(&dispute_key) {
            return Err(Error::DisputeAlreadyRecorded);
        }

        let mut badge = match badges::get_badge_impl(&env, &arbitrator) {
            Some(b) => b,
            None => {
                // Mint: one badge per arbitrator, token ids monotonic.
                let token_id: u64 = env
                    .storage()
                    .instance()
                    .get(&BadgeDataKey::BadgeCount)
                    .unwrap_or(0);
                env.storage()
                    .instance()
                    .set(&BadgeDataKey::BadgeCount, &(token_id + 1));

                let tier = BadgeTier::for_accurate(1).unwrap_or(BadgeTier::Bronze);
                let badge = Badge {
                    token_id,
                    owner: arbitrator.clone(),
                    tier,
                    accurate_resolutions: 1,
                    minted_at: env.ledger().sequence(),
                    last_resolution_ledger: env.ledger().sequence(),
                };
                badges::store(&env, &arbitrator, &badge);
                badges::mark_dispute(&env, dispute_id, &arbitrator);

                BadgeMintedEvent {
                    token_id,
                    owner: arbitrator.clone(),
                    tier: badge.tier,
                }
                .publish(&env);
                ResolutionRecordedEvent {
                    dispute_id,
                    owner: arbitrator.clone(),
                    accurate_resolutions: 1,
                    ledger: env.ledger().sequence(),
                }
                .publish(&env);
                return Ok(1);
            }
        };

        // Upgrade path: dedupe check first, then effects.
        let prev_tier = badge.tier;
        badge.accurate_resolutions += 1;
        badge.last_resolution_ledger = env.ledger().sequence();
        if let Some(new_tier) = BadgeTier::for_accurate(badge.accurate_resolutions) {
            if new_tier > prev_tier {
                badge.tier = new_tier;
            }
        }
        badges::store(&env, &arbitrator, &badge);
        badges::mark_dispute(&env, dispute_id, &arbitrator);

        if badge.tier > prev_tier {
            BadgeUpgradedEvent {
                token_id: badge.token_id,
                owner: arbitrator.clone(),
                from_tier: prev_tier,
                to_tier: badge.tier,
            }
            .publish(&env);
        }
        ResolutionRecordedEvent {
            dispute_id,
            owner: arbitrator.clone(),
            accurate_resolutions: badge.accurate_resolutions,
            ledger: env.ledger().sequence(),
        }
        .publish(&env);

        Ok(badge.accurate_resolutions)
    }

    /// Returns the badge held by `arbitrator`, if any. Read-only.
    pub fn get_badge(env: Env, arbitrator: Address) -> Option<Badge> {
        badges::get_badge_impl(&env, &arbitrator)
    }

    /// Returns the tier held by `arbitrator`, if any. Read-only.
    pub fn get_tier(env: Env, arbitrator: Address) -> Option<BadgeTier> {
        badges::get_badge_impl(&env, &arbitrator).map(|b| b.tier)
    }

    /// Returns the bound arbiter authority, if initialized. Read-only.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&BadgeDataKey::Admin)
    }

    /// Returns the number of badges ever minted. Read-only.
    pub fn total_badges(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&badges::DataKey::BadgeCount)
            .unwrap_or(0)
    }

    /// Returns the lifetime accuracy threshold for each tier. Read-only;
    /// clients should discover thresholds via this getter rather than
    /// hard-coding them.
    pub fn get_thresholds(_env: Env) -> (u64, u64, u64) {
        (
            badges::BRONZE_THRESHOLD,
            badges::SILVER_THRESHOLD,
            badges::GOLD_THRESHOLD,
        )
    }
}
