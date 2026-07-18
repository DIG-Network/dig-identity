//! The [`IdentityProfile`] primitive — the managed DIG Network "Profile" object.
//!
//! WIP stub (cap-safety first push). Filled in by TDD in this PR.

use crate::error::Result;
use crate::pairing::{IdentitySingleton, StoreRecord};
use crate::profile::Profile;

/// The managed DIG identity profile (STUB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProfile {
    singleton: IdentitySingleton,
    store: StoreRecord,
    metadata: Profile,
    root: [u8; 32],
}

impl IdentityProfile {
    /// STUB — resolve a paired identity profile from supplied records.
    pub fn resolve(
        singleton: IdentitySingleton,
        store: StoreRecord,
        metadata: Profile,
    ) -> Result<Self> {
        let root = metadata.build_root()?;
        Ok(Self {
            singleton,
            store,
            metadata,
            root,
        })
    }
}
