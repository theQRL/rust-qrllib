//! RFC 8391 reference-implementation interop for the XMSS parameter
//! sets QRL supports.
//!
//! # What this module is for
//!
//! QRL's [crate::xmss] implementation is signature-format compliant
//! with RFC 8391 (August 2018) for the XMSS-SHA2_h_256 and
//! XMSS-SHAKE_256_h_256 parameter sets — signatures it produces verify
//! correctly under the reference implementation at
//! <https://github.com/XMSS/xmss-reference>. The cross-implementation
//! verification CI in `.github/workflows/cross-verify.yml` confirms
//! this in the forward direction (rust-qrllib → reference).
//!
//! Two QRL-specific conventions, however, prevent the *opposite*
//! direction (reference → rust-qrllib) from working out of the box:
//!
//!  1. **Seed derivation.** [`crate::xmss::Xmss::initialize_tree`]
//!     expands a 48-byte seed via SHAKE-256 into the 96 bytes
//!     (SK_SEED || SK_PRF || PUB_SEED) the construction needs. The
//!     RFC 8391 reference takes those 96 bytes directly with no
//!     expansion step. So a 48-byte seed handed to both
//!     implementations does NOT produce the same keypair; only a
//!     96-byte expanded-seed handed to both does.
//!  2. **Public-key prefix.** QRL's extended-PK format prefixes the
//!     32-byte root and 32-byte pub_seed with a 3-byte QRL descriptor.
//!     RFC 8391 prefixes them with a 4-byte parameter-set OID.
//!
//! This module addresses both:
//!
//!   - [`new_keypair`] takes 96 bytes directly via
//!     [`crate::xmss::Xmss::initialize_tree_from_expanded_seed`],
//!     matching the reference implementation's keypair derivation.
//!   - [`marshal_public_key`] / [`unmarshal_public_key`] convert
//!     between QRL's internal representation and the RFC byte layout.
//!
//! Together they make cross-implementation interop bidirectional for
//! the supported parameter sets. Signature byte layouts already match
//! at the wire level — no conversion is needed for signatures.
//!
//! # Supported parameter sets
//!
//! RFC 8391 defines twelve parameter sets, identified by 32-bit OIDs.
//! QRL's implementation supports `n=32, w=16, k=2`, so the OIDs that
//! can round-trip through this module are:
//!
//!   - `XMSS-SHA2_10_256`  (OID 0x00000001)
//!   - `XMSS-SHA2_16_256`  (OID 0x00000002)
//!   - `XMSS-SHA2_20_256`  (OID 0x00000003)
//!   - `XMSS-SHAKE_10_256` (OID 0x00000007)
//!   - `XMSS-SHAKE_16_256` (OID 0x00000008)
//!   - `XMSS-SHAKE_20_256` (OID 0x00000009)
//!
//! The remaining six OIDs from RFC 8391 are `n=64` parameter sets
//! (XMSS-{SHA2,SHAKE}_h_512); they are out of scope for QRL and not
//! implemented. Calling [`new_keypair`] / [`unmarshal_public_key`]
//! with one of those OIDs returns
//! [`crate::error::QrllibError::UnsupportedXmssParameterSet`].
//!
//! QRL's pre-standardisation SHAKE_128 hash variant is not part of
//! RFC 8391 and has no OID; this module will not produce or consume
//! SHAKE_128 keys. Use the parent [`crate::xmss`] module directly for
//! those.
//!
//! # Standards alignment
//!
//! See `SECURITY.md` "Standards alignment" for the full discussion of
//! why this library implements the original RFC 8391 (Aug 2018)
//! `expand_seed` construction rather than the NIST SP 800-208
//! (Oct 2020) refinement. The cross-verify CI accommodates the
//! difference by pinning `xmss-reference` to commit `7793c40` (the
//! last revision on the original spec).
//!
//! (TOB-QRLLIB-1 part 2 — Rust-port parity with the Go-side
//! `crypto/xmss/rfc8391` sub-package.)

use crate::error::{QrllibError, Result};
use crate::xmss::{XMSS_PUBLIC_KEY_SIZE, Xmss, XmssHashFunction, XmssHeight, verify_xmss};

/// Length in bytes of the RFC 8391 OID prefix on a public key.
const OID_LEN: usize = 4;

/// Length in bytes of the pre-expanded seed material accepted by
/// [`new_keypair`] (`SK_SEED || SK_PRF || PUB_SEED`, 3 × 32 bytes).
pub const EXPANDED_SEED_SIZE: usize = 96;

/// Length in bytes of the RFC 8391 public-key layout
/// (`OID || root || pub_seed`).
pub const RFC_PUBLIC_KEY_SIZE: usize = OID_LEN + XMSS_PUBLIC_KEY_SIZE;

/// RFC 8391 parameter-set identifier (OID).
///
/// Only the six parameter sets that match QRL's supported
/// `(n=32, w=16, k=2)` family are enumerated here; the
/// twelve-OID-total spec list also includes six `n=64` parameter sets
/// (XMSS-{SHA2,SHAKE}_h_512) that QRL does not implement.
///
/// Variant naming follows the RFC 8391 spec literals (e.g.
/// `XMSS-SHA2_10_256`) with underscores preserved for readability; the
/// resulting Rust identifiers trip the clippy
/// `non_camel_case_types` lint but the spec-literal form is far more
/// recognisable to readers of the RFC than `XmssSha210256` would be.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ParameterSet {
    XmssSha2_10_256 = 0x00000001,
    XmssSha2_16_256 = 0x00000002,
    XmssSha2_20_256 = 0x00000003,
    XmssShake_10_256 = 0x00000007,
    XmssShake_16_256 = 0x00000008,
    XmssShake_20_256 = 0x00000009,
}

impl ParameterSet {
    /// Parse a 32-bit RFC 8391 OID into a [`ParameterSet`]. Returns
    /// [`QrllibError::UnsupportedXmssParameterSet`] for any OID
    /// outside the QRL-supported set listed in the module doc.
    pub fn from_oid(oid: u32) -> Result<Self> {
        match oid {
            0x00000001 => Ok(Self::XmssSha2_10_256),
            0x00000002 => Ok(Self::XmssSha2_16_256),
            0x00000003 => Ok(Self::XmssSha2_20_256),
            0x00000007 => Ok(Self::XmssShake_10_256),
            0x00000008 => Ok(Self::XmssShake_16_256),
            0x00000009 => Ok(Self::XmssShake_20_256),
            _ => Err(QrllibError::UnsupportedXmssParameterSet(oid)),
        }
    }

    /// The 32-bit RFC 8391 OID for this parameter set.
    pub const fn oid(self) -> u32 {
        self as u32
    }

    /// The tree height for this parameter set (10, 16, or 20).
    pub fn height(self) -> XmssHeight {
        let h = match self {
            Self::XmssSha2_10_256 | Self::XmssShake_10_256 => 10_u8,
            Self::XmssSha2_16_256 | Self::XmssShake_16_256 => 16_u8,
            Self::XmssSha2_20_256 | Self::XmssShake_20_256 => 20_u8,
        };
        // Invariant tripwire — h is one of {10, 16, 20}, all of which
        // are valid even heights in [2, XMSS_MAX_HEIGHT]; XmssHeight::new
        // cannot fail here. See `SECURITY.md` "Panic policy".
        XmssHeight::new(h).expect("ParameterSet heights {10, 16, 20} are all valid XmssHeights")
    }

    /// The hash function used by this parameter set.
    pub const fn hash_function(self) -> XmssHashFunction {
        match self {
            Self::XmssSha2_10_256 | Self::XmssSha2_16_256 | Self::XmssSha2_20_256 => {
                XmssHashFunction::Sha2_256
            }
            Self::XmssShake_10_256 | Self::XmssShake_16_256 | Self::XmssShake_20_256 => {
                XmssHashFunction::Shake256
            }
        }
    }
}

/// Construct an XMSS tree from a 96-byte expanded seed, matching the
/// RFC 8391 reference implementation's keypair derivation.
///
/// To construct an XMSS that round-trips with the reference: take the
/// same 96-byte seed material both sides consume, pass it here, and
/// compare the resulting `root || pub_seed` against the reference's
/// output.
///
/// The QRL [`crate::xmss::Xmss::initialize_tree`] entry point is the
/// wrong choice for this use case — it expands a 48-byte seed via
/// SHAKE-256 first, which the RFC reference does not.
pub fn new_keypair(p: ParameterSet, expanded_seed: &[u8; EXPANDED_SEED_SIZE]) -> Result<Xmss> {
    Xmss::initialize_tree_from_expanded_seed(p.height(), p.hash_function(), expanded_seed)
}

/// Marshal an XMSS public key into the RFC 8391 layout
/// (`OID || root || pub_seed`, 68 bytes total).
pub fn marshal_public_key(xmss: &Xmss, p: ParameterSet) -> [u8; RFC_PUBLIC_KEY_SIZE] {
    let mut out = [0_u8; RFC_PUBLIC_KEY_SIZE];
    out[..OID_LEN].copy_from_slice(&p.oid().to_be_bytes());
    out[OID_LEN..].copy_from_slice(&xmss.public_key());
    out
}

/// Unmarshal an RFC 8391-format public key into its parameter set,
/// 32-byte Merkle root, and 32-byte public seed.
///
/// Returns [`QrllibError::UnsupportedXmssParameterSet`] if the OID
/// prefix is not one of the QRL-supported set.
pub fn unmarshal_public_key(
    bytes: &[u8; RFC_PUBLIC_KEY_SIZE],
) -> Result<(ParameterSet, [u8; 32], [u8; 32])> {
    let mut oid_buf = [0_u8; 4];
    oid_buf.copy_from_slice(&bytes[..4]);
    let oid = u32::from_be_bytes(oid_buf);
    let p = ParameterSet::from_oid(oid)?;
    let mut root = [0_u8; 32];
    let mut pub_seed = [0_u8; 32];
    root.copy_from_slice(&bytes[4..36]);
    pub_seed.copy_from_slice(&bytes[36..68]);
    Ok((p, root, pub_seed))
}

/// Verify an XMSS signature using an RFC 8391-format public key.
///
/// Returns `false` for any of: an OID that doesn't match the supplied
/// parameter set `p`, a parameter-set / hash-function mismatch, or a
/// failed signature verification.
pub fn verify(
    p: ParameterSet,
    message: &[u8],
    signature: &[u8],
    rfc_pk: &[u8; RFC_PUBLIC_KEY_SIZE],
) -> bool {
    let (decoded_p, _root, _pub_seed) = match unmarshal_public_key(rfc_pk) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if decoded_p != p {
        return false;
    }
    // `verify_xmss` consumes the QRL-internal (root || pub_seed) pk
    // layout — the same 64 bytes that follow the 4-byte OID prefix.
    verify_xmss(p.hash_function(), message, signature, &rfc_pk[OID_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascending_expanded_seed() -> [u8; EXPANDED_SEED_SIZE] {
        let mut seed = [0_u8; EXPANDED_SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        seed
    }

    #[test]
    fn from_oid_round_trips() {
        for &(oid, expected) in &[
            (0x00000001_u32, ParameterSet::XmssSha2_10_256),
            (0x00000002, ParameterSet::XmssSha2_16_256),
            (0x00000003, ParameterSet::XmssSha2_20_256),
            (0x00000007, ParameterSet::XmssShake_10_256),
            (0x00000008, ParameterSet::XmssShake_16_256),
            (0x00000009, ParameterSet::XmssShake_20_256),
        ] {
            let p = ParameterSet::from_oid(oid).expect("supported oid");
            assert_eq!(p, expected);
            assert_eq!(p.oid(), oid);
        }
    }

    #[test]
    fn from_oid_rejects_unsupported() {
        // 0x00000004..0x00000006 are XMSS-SHA2_h_512 (n=64) — not in scope.
        for oid in [0x00000004_u32, 0x00000005, 0x00000006, 0x0000000a, 0xffffffff] {
            let err = ParameterSet::from_oid(oid).unwrap_err();
            assert!(matches!(err, QrllibError::UnsupportedXmssParameterSet(o) if o == oid));
        }
    }

    #[test]
    fn keypair_marshal_unmarshal_round_trip() {
        let seed = ascending_expanded_seed();
        let tree =
            new_keypair(ParameterSet::XmssSha2_10_256, &seed).expect("keypair from expanded seed");

        let rfc_pk = marshal_public_key(&tree, ParameterSet::XmssSha2_10_256);
        // OID prefix is big-endian 0x00000001.
        assert_eq!(&rfc_pk[..4], &[0x00, 0x00, 0x00, 0x01]);
        // PUB_SEED in the marshalled layout equals seed[64..96] (the
        // expanded-seed `PUB_SEED` slot consumed unchanged).
        assert_eq!(&rfc_pk[36..68], &seed[64..96]);

        let (p, root, pub_seed) = unmarshal_public_key(&rfc_pk).expect("unmarshal");
        assert_eq!(p, ParameterSet::XmssSha2_10_256);
        assert_eq!(&pub_seed, &seed[64..96]);
        // The 32-byte root field of the unmarshalled pk equals what
        // `Xmss::public_key()` reports for the first 32 bytes (it
        // returns root || pub_seed).
        assert_eq!(&root, &tree.public_key()[..32]);
    }

    #[test]
    fn verify_accepts_in_house_signature_with_rfc_pk() {
        let seed = ascending_expanded_seed();
        let mut tree =
            new_keypair(ParameterSet::XmssSha2_10_256, &seed).expect("keypair from expanded seed");
        let message = b"rfc8391 module round-trip";
        let signature = tree.sign(message).expect("sign");
        let rfc_pk = marshal_public_key(&tree, ParameterSet::XmssSha2_10_256);

        assert!(verify(ParameterSet::XmssSha2_10_256, message, &signature, &rfc_pk));

        // Parameter-set mismatch is rejected.
        assert!(!verify(ParameterSet::XmssSha2_16_256, message, &signature, &rfc_pk));

        // Tampered message → false.
        assert!(!verify(ParameterSet::XmssSha2_10_256, b"tampered", &signature, &rfc_pk));
    }

    #[test]
    fn distinct_seeds_produce_distinct_roots() {
        let mut seed_a = ascending_expanded_seed();
        seed_a[0] ^= 0x01;
        let mut seed_b = ascending_expanded_seed();
        seed_b[0] ^= 0x02;

        let tree_a = new_keypair(ParameterSet::XmssSha2_10_256, &seed_a).expect("a");
        let tree_b = new_keypair(ParameterSet::XmssSha2_10_256, &seed_b).expect("b");

        assert_ne!(tree_a.public_key(), tree_b.public_key());
    }
}
