use std::{fs, process::ExitCode};

use qrllib::{ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, mldsa::verify_bytes};

fn main() -> ExitCode {
    let public_key = fs::read("/tmp/ref_mldsa_pk.bin").expect("read public key");
    let signature = fs::read("/tmp/ref_mldsa_sig.bin").expect("read signature");
    let message = fs::read("/tmp/ref_mldsa_msg.bin").expect("read message");
    let context = fs::read("/tmp/ref_mldsa_ctx.bin").expect("read context");

    if public_key.len() != ML_DSA_87_PUBLIC_KEY_SIZE {
        eprintln!(
            "PK size mismatch: got {}, expected {}",
            public_key.len(),
            ML_DSA_87_PUBLIC_KEY_SIZE
        );
        return ExitCode::FAILURE;
    }
    if signature.len() != ML_DSA_87_SIGNATURE_SIZE {
        eprintln!(
            "Sig size mismatch: got {}, expected {}",
            signature.len(),
            ML_DSA_87_SIGNATURE_SIZE
        );
        return ExitCode::FAILURE;
    }

    let valid = match verify_bytes(&context, &message, &signature, &public_key) {
        Ok(valid) => valid,
        Err(error) => {
            eprintln!("verify error: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("rust-qrllib ML-DSA-87 verifier:");
    println!("  PK size:  {} bytes", public_key.len());
    println!("  Sig size: {} bytes", signature.len());
    println!("  Context:  {}", String::from_utf8_lossy(&context));
    println!("  Verification: {}", if valid { "PASSED" } else { "FAILED" });

    if valid { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
