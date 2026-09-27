//! Soulbound token types for the reputation registry (issue #450).
//!
//! The credential itself is deliberately inert: a [`SoulboundToken`] is a
//! plain `#[contracttype]` record with no methods that could move it, and it
//! lives under a storage key derived from its owner, so "holding" it and
//! "being it" are the same thing. Tier classification lives here too — the
//! issue that introduces tiered arbitrator badges will build on this enum.

use soroban_sdk::{contracttype, String};

/// The tier of a soulbound credential.
///
/// Serialized discriminants are part of the public interface (indexers read
/// them from the WASM spec); do not renumber.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CredentialClass {
    /// KYC-verified merchant: the entry-level credential.
    Verified = 1,
    /// Sustained-volume merchant with an unblemished record.
    Trusted = 2,
    /// Top-tier merchant: high volume, long tenure, zero adversarial
    /// outcomes.
    Premium = 3,
}

impl CredentialClass {
    /// Decode a caller-supplied class id, or `None` if it is not a valid
    /// [`CredentialClass`] discriminant.
    pub fn from_repr(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Verified),
            2 => Some(Self::Trusted),
            3 => Some(Self::Premium),
            _ => None,
        }
    }
}

/// A non-transferable credential permanently bound to one address.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoulboundToken {
    /// Monotonic token id assigned at mint time (0-based). Not unique after
    /// a revoke + re-issue, but the `(token_id, owner)` event topics pin the
    /// history for indexers.
    pub token_id: u64,
    /// Tier assigned at mint time. A credential is never upgraded in place;
    /// governance revokes and re-issues at the new tier.
    pub class: CredentialClass,
    /// Ledger at which the credential was minted.
    pub issued_at: u32,
    /// Whether governance slashed this credential.
    pub slashed: bool,
    /// Ledger at which the slash happened, if any.
    pub slashed_at: Option<u32>,
    /// Public reason recorded for the slash, if any.
    pub reason: Option<String>,
}
