//! The UPDATE-AUTHORITY predicate for a profile's DataLayer store — the fail-closed guard on the
//! profile-update path (#1361 / #908).
//!
//! A profile's SMT root can only ADVANCE by spending the store singleton to recreate it with a new
//! root — a spend the chain accepts ONLY from an authorized party. Two forms of authority let a
//! caller land that advance:
//!
//! 1. **Owner** — the caller's puzzle satisfies the store singleton's CURRENT owner puzzle hash.
//! 2. **Delegate** — the caller holds a CURRENTLY-VALID CHIP-0035 writer/admin delegation on the
//!    store (not revoked, not past its expiry height).
//!
//! An `Oracle` delegation ([`DelegationKind::Oracle`]) grants a READ-FEE right, **NOT** write authority, so it
//! NEVER authorizes an update. That distinction is the security property this module exists to hold.
//!
//! # This module is the DECISION only
//!
//! dig-identity is a level-00 crate: it may depend on no other DIG crate, and in particular not on
//! `dig-store`. So the two chain-touching halves of the update path live one level up (in
//! `dig-social-profile` today):
//!
//! * the **chain-reading seam** that resolves the owner puzzle hash, the recorded delegations, and
//!   the current height from chain, and
//! * the **spend builder** that turns an authorized advance into an unsigned DataLayer update spend.
//!
//! What lives HERE is the pure predicate [`StoreUpdateAuthority::authorizes`], which decides the two
//! forms of authority over already-resolved chain facts. Keeping the decision separate from the
//! source mirrors the crate's trust model ([`crate::resolve`]): a source reports chain FACTS only;
//! the DECISION lives in the crate, is total, and fails closed.

use chia_protocol::Bytes32;

/// The kind of a CHIP-0035 delegation, which determines whether it grants WRITE authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationKind {
    /// A writer may advance the store root — grants update authority.
    Writer,
    /// An admin may advance the store root and manage delegations — grants update authority.
    Admin,
    /// An oracle may collect the read fee — it does NOT grant update authority.
    Oracle,
}

impl DelegationKind {
    /// Whether this delegation kind grants authority to advance (update) the store root.
    ///
    /// Only [`Writer`](Self::Writer) and [`Admin`](Self::Admin) do; [`Oracle`](Self::Oracle) is a
    /// read-fee right and never grants write authority.
    #[must_use]
    pub fn grants_update(self) -> bool {
        matches!(self, DelegationKind::Writer | DelegationKind::Admin)
    }
}

/// A CHIP-0035 delegation recorded on the store singleton, as read from current chain state.
///
/// A delegation authorizes an update ONLY when it is a write-granting kind ([`DelegationKind::Writer`]
/// / [`DelegationKind::Admin`]), is NOT revoked, and has NOT expired (see
/// [`StoreUpdateAuthority::authorizes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterDelegation {
    /// The delegate's puzzle hash — the party this delegation authorizes.
    pub delegate_puzzle_hash: Bytes32,
    /// The delegation kind (writer / admin grant update authority; oracle does not).
    pub kind: DelegationKind,
    /// Whether the delegation has been revoked on-chain (a revocation spend removed it). A revoked
    /// delegation NEVER authorizes.
    pub revoked: bool,
    /// The block height at/after which the delegation is expired, if it carries an expiry. `None` means
    /// it never expires; `Some(h)` means it is invalid once `current_height >= h`.
    pub expires_at_height: Option<u32>,
}

impl WriterDelegation {
    /// Whether this delegation authorizes an update for `caller_puzzle_hash` at `current_height`.
    ///
    /// True iff the delegate matches, the kind grants update authority, it is not revoked, and (if it
    /// has an expiry) the current height is strictly before it. Every failing condition fails CLOSED.
    #[must_use]
    fn authorizes(&self, caller_puzzle_hash: Bytes32, current_height: u32) -> bool {
        self.delegate_puzzle_hash == caller_puzzle_hash
            && self.kind.grants_update()
            && !self.revoked
            && self
                .expires_at_height
                .map_or(true, |expiry| current_height < expiry)
    }
}

/// The store singleton's CURRENT on-chain update authority — everything needed to DECIDE whether a
/// caller may advance the store root, as resolved from chain by a higher-level chain source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreUpdateAuthority {
    /// The store singleton's current owner puzzle hash. A caller whose puzzle hash equals this holds
    /// full update authority.
    pub owner_puzzle_hash: Bytes32,
    /// The CHIP-0035 delegations currently recorded on the store (any kind; validity is decided by
    /// [`Self::authorizes`], not by the source).
    pub delegations: Vec<WriterDelegation>,
    /// The current chain height, used to evaluate delegation expiry.
    pub current_height: u32,
}

impl StoreUpdateAuthority {
    /// Whether `caller_puzzle_hash` is authorized to advance (update) this store's root.
    ///
    /// True iff the caller is the current owner OR holds a currently-valid write-granting delegation.
    /// Fails closed: an unknown caller, a revoked or expired delegation, or an oracle-only delegation
    /// all return `false`.
    ///
    /// # Misuse boundary (MUST read)
    ///
    /// This is a **pre-flight predicate over chain facts the CALLER has already authenticated**. It
    /// MUST NOT be evaluated over data supplied by the party being authorized: whoever controls
    /// `owner_puzzle_hash` or `delegations` controls the answer outright. Resolve those fields from
    /// chain (see [`crate::resolve`]'s trust model) before calling.
    ///
    /// A `true` here is NOT proof of on-chain authority — only the chain, accepting the spend, is
    /// that. Use this to decide whether an update is worth ATTEMPTING (and to fail fast when it is
    /// plainly not), never as the sole authorization for an action with consequences.
    #[must_use]
    pub fn authorizes(&self, caller_puzzle_hash: Bytes32) -> bool {
        if caller_puzzle_hash == self.owner_puzzle_hash {
            return true;
        }
        self.delegations
            .iter()
            .any(|delegation| delegation.authorizes(caller_puzzle_hash, self.current_height))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ph(byte: u8) -> Bytes32 {
        Bytes32::new([byte; 32])
    }

    const OWNER: u8 = 0x01;
    const WRITER: u8 = 0x02;
    const STRANGER: u8 = 0x03;

    fn delegation(ph_byte: u8, kind: DelegationKind) -> WriterDelegation {
        WriterDelegation {
            delegate_puzzle_hash: ph(ph_byte),
            kind,
            revoked: false,
            expires_at_height: None,
        }
    }

    fn authority(delegations: Vec<WriterDelegation>, current_height: u32) -> StoreUpdateAuthority {
        StoreUpdateAuthority {
            owner_puzzle_hash: ph(OWNER),
            delegations,
            current_height,
        }
    }

    #[test]
    fn owner_is_authorized() {
        assert!(authority(vec![], 100).authorizes(ph(OWNER)));
    }

    #[test]
    fn stranger_with_no_delegation_is_rejected() {
        assert!(!authority(vec![], 100).authorizes(ph(STRANGER)));
    }

    #[test]
    fn valid_writer_delegation_authorizes() {
        let auth = authority(vec![delegation(WRITER, DelegationKind::Writer)], 100);
        assert!(auth.authorizes(ph(WRITER)));
    }

    #[test]
    fn valid_admin_delegation_authorizes() {
        let auth = authority(vec![delegation(WRITER, DelegationKind::Admin)], 100);
        assert!(auth.authorizes(ph(WRITER)));
    }

    #[test]
    fn oracle_delegation_does_not_authorize_an_update() {
        let auth = authority(vec![delegation(WRITER, DelegationKind::Oracle)], 100);
        assert!(!auth.authorizes(ph(WRITER)));
    }

    #[test]
    fn revoked_delegation_is_rejected() {
        let mut revoked = delegation(WRITER, DelegationKind::Writer);
        revoked.revoked = true;
        assert!(!authority(vec![revoked], 100).authorizes(ph(WRITER)));
    }

    #[test]
    fn expired_delegation_is_rejected() {
        let mut expiring = delegation(WRITER, DelegationKind::Writer);
        expiring.expires_at_height = Some(50);
        // current height 100 is >= the expiry 50 -> expired.
        assert!(!authority(vec![expiring], 100).authorizes(ph(WRITER)));
    }

    #[test]
    fn delegation_valid_right_up_to_expiry_height() {
        let mut expiring = delegation(WRITER, DelegationKind::Writer);
        expiring.expires_at_height = Some(50);
        // height 49 < 50 -> still valid; height 50 -> expired (invalid at/after).
        assert!(authority(vec![expiring.clone()], 49).authorizes(ph(WRITER)));
        assert!(!authority(vec![expiring], 50).authorizes(ph(WRITER)));
    }

    #[test]
    fn delegation_for_a_different_caller_is_rejected() {
        let auth = authority(vec![delegation(WRITER, DelegationKind::Writer)], 100);
        assert!(!auth.authorizes(ph(STRANGER)));
    }

    #[test]
    fn owner_is_authorized_even_when_a_delegation_is_revoked() {
        let mut revoked = delegation(WRITER, DelegationKind::Writer);
        revoked.revoked = true;
        assert!(authority(vec![revoked], 100).authorizes(ph(OWNER)));
    }

    /// The owner short-circuit must hold against an EXPIRED delegation too, not only a revoked one.
    ///
    /// The revoked case above leaves the expiry arm of the short-circuit unexercised: an
    /// implementation that returned early only when every delegation is revoked would still pass it.
    #[test]
    fn owner_is_authorized_even_when_a_delegation_is_expired() {
        let mut expired = delegation(WRITER, DelegationKind::Writer);
        expired.expires_at_height = Some(50);
        assert!(authority(vec![expired], 100).authorizes(ph(OWNER)));
    }

    /// `expires_at_height = Some(0)` is a delegation that is NEVER valid: no height is `< 0`.
    ///
    /// It is the degenerate end of the strictly-less-than rule and is easy to special-case wrongly
    /// (treating `Some(0)` as "no expiry"), which would fail OPEN. SPEC §8.3 states it normatively.
    #[test]
    fn delegation_expiring_at_height_zero_never_authorizes() {
        let mut never_valid = delegation(WRITER, DelegationKind::Writer);
        never_valid.expires_at_height = Some(0);
        assert!(!authority(vec![never_valid.clone()], 0).authorizes(ph(WRITER)));
        assert!(!authority(vec![never_valid], 100).authorizes(ph(WRITER)));
    }

    /// SPEC §8.3 requires SOME recorded delegation to authorize — an existential over the whole list.
    ///
    /// Every other test here carries zero or one delegation, so all of them pass an implementation
    /// that inspects only the FIRST entry (`delegations.first().is_some_and(..)`). This fixture puts a
    /// NON-authorizing delegation for the caller FIRST — same delegate, `Oracle`, i.e. a match on the
    /// delegate that fails on kind — and the authorizing one SECOND, so a first-only implementation
    /// answers `false` where the spec requires `true`.
    #[test]
    fn a_later_delegation_authorizes_when_an_earlier_one_does_not() {
        let auth = authority(
            vec![
                delegation(WRITER, DelegationKind::Oracle),
                delegation(WRITER, DelegationKind::Writer),
            ],
            100,
        );
        assert!(auth.authorizes(ph(WRITER)));
    }

    /// A puzzle hash differing from the owner's in its LAST byte only.
    ///
    /// Every other fixture is `[byte; 32]`, so any two differ in EVERY byte — under which a comparison
    /// narrowed to one byte, or truncated to a prefix, still separates them. These twins do not.
    fn twin(last_byte: u8) -> Bytes32 {
        let mut bytes = [0xAA; 32];
        bytes[31] = last_byte;
        Bytes32::new(bytes)
    }

    #[test]
    fn a_puzzle_hash_differing_only_in_its_last_byte_is_not_the_owner() {
        let auth = StoreUpdateAuthority {
            owner_puzzle_hash: twin(0xAA),
            delegations: vec![],
            current_height: 100,
        };
        assert!(auth.authorizes(twin(0xAA)));
        assert!(!auth.authorizes(twin(0xAB)));
    }

    #[test]
    fn a_delegation_does_not_authorize_a_twin_differing_only_in_its_last_byte() {
        let auth = StoreUpdateAuthority {
            owner_puzzle_hash: ph(OWNER),
            delegations: vec![WriterDelegation {
                delegate_puzzle_hash: twin(0xAA),
                kind: DelegationKind::Writer,
                revoked: false,
                expires_at_height: None,
            }],
            current_height: 100,
        };
        assert!(auth.authorizes(twin(0xAA)));
        assert!(!auth.authorizes(twin(0xAB)));
    }
}
