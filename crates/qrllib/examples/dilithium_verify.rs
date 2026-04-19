use std::{fs, process::ExitCode};

use qrllib::{DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SIGNATURE_SIZE, verify_dilithium_signature};

fn main() -> ExitCode {
    let public_key = fs::read("/tmp/ref_dilithium_pk.bin").expect("read public key");
    let signature = fs::read("/tmp/ref_dilithium_sig.bin").expect("read signature");
    let message = fs::read("/tmp/ref_dilithium_msg.bin").expect("read message");

    if public_key.len() != DILITHIUM_PUBLIC_KEY_SIZE {
        eprintln!(
            "PK size mismatch: got {}, expected {}",
            public_key.len(),
            DILITHIUM_PUBLIC_KEY_SIZE
        );
        return ExitCode::FAILURE;
    }
    if signature.len() != DILITHIUM_SIGNATURE_SIZE {
        eprintln!(
            "Sig size mismatch: got {}, expected {}",
            signature.len(),
            DILITHIUM_SIGNATURE_SIZE
        );
        return ExitCode::FAILURE;
    }

    let valid = verify_dilithium_signature(&message, &signature, &public_key);
    println!("rust-qrllib Dilithium5 verifier:");
    println!("  PK size:  {} bytes", public_key.len());
    println!("  Sig size: {} bytes", signature.len());
    println!("  Verification: {}", if valid { "PASSED" } else { "FAILED" });

    if valid { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
