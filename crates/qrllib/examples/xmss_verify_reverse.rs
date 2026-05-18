//! Reverse-direction XMSS cross-verify counterpart to `xmss_sign.rs`.
//!
//! Reads the artefacts written by `.github/cross-verify/xmss_sign_ref.c`
//! (the reference implementation, pinned to commit `7793c40` —
//! pre-SP-800-208 RFC 8391), reconstructs the keypair from the same
//! 96-byte expanded seed via the `qrllib::xmss::rfc8391` interop
//! sub-package, asserts the resulting `root || pub_seed` matches the
//! reference's PK byte-for-byte, then verifies the signature via
//! [`qrllib::xmss::rfc8391::verify`]. The pk-bytes-match check is the
//! bidirectional-equivalence proof; signature verification is then a
//! straightforward consequence.
//!
//! TOB-QRLLIB-1 part 2 — Rust-port parity with the Go-side
//! `.github/cross-verify/xmss_verify.go`.

use std::{fs, process::ExitCode};

use qrllib::xmss::rfc8391::{
    self, EXPANDED_SEED_SIZE, ParameterSet, RFC_PUBLIC_KEY_SIZE,
};

const PK_SIZE: usize = 64; // root (32) || pub_seed (32)

fn read_or_die(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("Cannot read {}: {}", path, e);
        std::process::exit(1)
    })
}

fn main() -> ExitCode {
    let pk_bytes = read_or_die("/tmp/xmss_ref_pk.bin");
    if pk_bytes.len() != PK_SIZE {
        eprintln!("xmss_ref_pk.bin: got {} bytes, want {}", pk_bytes.len(), PK_SIZE);
        return ExitCode::from(1);
    }

    let rfc_pk_bytes = read_or_die("/tmp/xmss_ref_pk_rfc.bin");
    if rfc_pk_bytes.len() != RFC_PUBLIC_KEY_SIZE {
        eprintln!(
            "xmss_ref_pk_rfc.bin: got {} bytes, want {}",
            rfc_pk_bytes.len(),
            RFC_PUBLIC_KEY_SIZE
        );
        return ExitCode::from(1);
    }
    let mut rfc_pk = [0_u8; RFC_PUBLIC_KEY_SIZE];
    rfc_pk.copy_from_slice(&rfc_pk_bytes);

    let signature = read_or_die("/tmp/xmss_ref_sig.bin");
    let message = read_or_die("/tmp/xmss_ref_msg.bin");

    let expanded_seed_bytes = read_or_die("/tmp/xmss_ref_expanded_seed.bin");
    if expanded_seed_bytes.len() != EXPANDED_SEED_SIZE {
        eprintln!(
            "xmss_ref_expanded_seed.bin: got {} bytes, want {}",
            expanded_seed_bytes.len(),
            EXPANDED_SEED_SIZE
        );
        return ExitCode::from(1);
    }
    let mut expanded_seed = [0_u8; EXPANDED_SEED_SIZE];
    expanded_seed.copy_from_slice(&expanded_seed_bytes);

    // Reconstruct the keypair from the same 96 bytes the reference
    // used. If the keypair-derivation equivalence holds, this
    // rust-qrllib tree's pk should match the reference's pk
    // byte-for-byte.
    let tree = match rfc8391::new_keypair(ParameterSet::XmssSha2_10_256, &expanded_seed) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("rfc8391::new_keypair: {:?}", e);
            return ExitCode::from(1);
        }
    };

    let our_pk = tree.public_key();
    if our_pk[..] != pk_bytes[..] {
        eprintln!("Keypair-derivation mismatch:");
        eprintln!("  reference pk: {}", hex::encode(&pk_bytes));
        eprintln!("  rust-qrllib pk: {}", hex::encode(our_pk));
        return ExitCode::from(1);
    }

    // Verify the reference's signature against the keypair we just
    // reconstructed (via the RFC-format public key, exercising the
    // full sub-module surface).
    let ok = rfc8391::verify(ParameterSet::XmssSha2_10_256, &message, &signature, &rfc_pk);

    println!("rust-qrllib XMSS-SHA2_10_256 verifier:");
    println!("  Reference PK (root||pub_seed): {} bytes", pk_bytes.len());
    println!("  Reference PK (RFC layout):     {} bytes", rfc_pk_bytes.len());
    println!("  Signature:                     {} bytes", signature.len());
    println!("  Message:                       {} bytes", message.len());
    println!("  Keypair-derivation match:      PASSED");
    if ok {
        println!("  Signature verification:        PASSED");
        ExitCode::from(0)
    } else {
        println!("  Signature verification:        FAILED");
        ExitCode::from(1)
    }
}
