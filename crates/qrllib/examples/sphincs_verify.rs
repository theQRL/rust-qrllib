use std::{fs, process::ExitCode};

use qrllib::{
    SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE,
    verify_sphincsplus_signature,
};

fn main() -> ExitCode {
    let public_key = fs::read("/tmp/ref_sphincs_pk.bin").expect("read public key");
    let signature = fs::read("/tmp/ref_sphincs_sig.bin").expect("read signature");
    let message = fs::read("/tmp/ref_sphincs_msg.bin").expect("read message");

    if public_key.len() != SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE {
        eprintln!(
            "PK size mismatch: got {}, expected {}",
            public_key.len(),
            SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE
        );
        return ExitCode::FAILURE;
    }
    if signature.len() != SPHINCS_PLUS_256S_SIGNATURE_SIZE {
        eprintln!(
            "Sig size mismatch: got {}, expected {}",
            signature.len(),
            SPHINCS_PLUS_256S_SIGNATURE_SIZE
        );
        return ExitCode::FAILURE;
    }

    let valid = verify_sphincsplus_signature(&message, &signature, &public_key);

    println!("rust-qrllib SPHINCS+ SHAKE-256s-robust verifier:");
    println!("  PK size:  {} bytes", public_key.len());
    println!("  Sig size: {} bytes", signature.len());
    println!("  Verification: {}", if valid { "PASSED" } else { "FAILED" });

    if valid { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
