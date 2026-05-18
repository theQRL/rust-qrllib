use crate::{DESCRIPTOR_SIZE, descriptor::Descriptor};

/// Current signing-context format version.
///
/// Bumping this value is a hard break of the signature wire format: all
/// signatures produced under a new version will fail to verify under the
/// old version and vice-versa. A version bump must coincide with a
/// coordinated consensus / library activation.
pub const SIGNING_CONTEXT_VERSION: u8 = 0x01;

/// Application-domain tag embedded in every signature's context.
pub const SIGNING_CONTEXT_PREFIX: [u8; 4] = *b"ZOND";

/// Fixed on-wire length of a signing context constructed by [`signing_context`].
pub const SIGNING_CONTEXT_SIZE: usize = SIGNING_CONTEXT_PREFIX.len() + 1 + DESCRIPTOR_SIZE;

/// Build the domain-separated bytes that bind a signature to its descriptor:
///
/// `"ZOND" || SIGNING_CONTEXT_VERSION || descriptor`  (fixed 8 bytes)
///
/// The descriptor is embedded verbatim (type byte + reserved metadata bytes),
/// so any change to wallet type or future metadata produces a distinct
/// context. The version byte allows a later redesign of the context layout
/// without colliding with the current scheme.
///
/// The layout is fixed-length, so the downstream consumers (ML-DSA-87's
/// length-prefixed pre-string, or the SPHINCS+-256s message prefix) receive
/// an unambiguous, canonically-encoded byte string.
pub fn signing_context(descriptor: Descriptor) -> [u8; SIGNING_CONTEXT_SIZE] {
    let desc_bytes = descriptor.to_bytes();
    let mut out = [0_u8; SIGNING_CONTEXT_SIZE];
    out[..SIGNING_CONTEXT_PREFIX.len()].copy_from_slice(&SIGNING_CONTEXT_PREFIX);
    out[SIGNING_CONTEXT_PREFIX.len()] = SIGNING_CONTEXT_VERSION;
    out[SIGNING_CONTEXT_PREFIX.len() + 1..].copy_from_slice(&desc_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        SIGNING_CONTEXT_PREFIX, SIGNING_CONTEXT_SIZE, SIGNING_CONTEXT_VERSION, signing_context,
    };
    use crate::{descriptor::Descriptor, wallet_type::WalletType};

    #[test]
    fn canonical_descriptor_produces_expected_bytes() {
        let ctx = signing_context(Descriptor::mldsa87());
        assert_eq!(
            ctx,
            [b'Z', b'O', b'N', b'D', SIGNING_CONTEXT_VERSION, WalletType::MlDsa87.code(), 0, 0]
        );
        assert_eq!(ctx.len(), SIGNING_CONTEXT_SIZE);
    }

    #[test]
    fn different_descriptors_produce_distinct_contexts() {
        let ml = signing_context(Descriptor::mldsa87());
        let sp = signing_context(Descriptor::sphincsplus256s());
        assert_ne!(ml, sp, "contexts for different wallet types must not collide");

        let base = signing_context(Descriptor::new([WalletType::MlDsa87.code(), 0, 0]));
        let byte1 = signing_context(Descriptor::new([WalletType::MlDsa87.code(), 0x01, 0]));
        let byte2 = signing_context(Descriptor::new([WalletType::MlDsa87.code(), 0, 0x01]));
        assert_ne!(base, byte1, "metadata byte 1 must change the context");
        assert_ne!(base, byte2, "metadata byte 2 must change the context");
        assert_ne!(byte1, byte2, "distinct metadata bits must produce distinct contexts");
    }

    #[test]
    fn layout_is_fixed_length_and_encodes_prefix_version_descriptor() {
        for descriptor in [
            Descriptor::mldsa87(),
            Descriptor::sphincsplus256s(),
            Descriptor::new([WalletType::MlDsa87.code(), 0xff, 0xff]),
            Descriptor::new([WalletType::SphincsPlus256s.code(), 0x12, 0x34]),
        ] {
            let ctx = signing_context(descriptor);
            assert_eq!(ctx.len(), SIGNING_CONTEXT_SIZE);
            assert_eq!(&ctx[..SIGNING_CONTEXT_PREFIX.len()], &SIGNING_CONTEXT_PREFIX);
            assert_eq!(ctx[SIGNING_CONTEXT_PREFIX.len()], SIGNING_CONTEXT_VERSION);
            assert_eq!(&ctx[SIGNING_CONTEXT_PREFIX.len() + 1..], &descriptor.to_bytes());
        }
    }
}
