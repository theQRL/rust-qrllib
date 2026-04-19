use std::{fs, process::ExitCode};

use qrllib::{ML_DSA_87_CRYPTO_SEED_SIZE, MlDsa87, mldsa::verify_bytes};

fn main() -> ExitCode {
    let mut seed = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let signer = MlDsa87::from_seed(seed);
    let public_key = signer.public_key_bytes();
    let context = b"test";
    let message = b"ML-DSA-87 cross-implementation verification";
    let signature = match signer.sign(context, message) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("sign error: {error}");
            return ExitCode::FAILURE;
        }
    };

    match verify_bytes(context, message, &signature, &public_key) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("self-verification failed");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("verify error: {error}");
            return ExitCode::FAILURE;
        }
    }

    fs::write("/tmp/mldsa_pk.bin", public_key).expect("write public key");
    fs::write("/tmp/mldsa_sig.bin", signature).expect("write signature");
    fs::write("/tmp/mldsa_msg.bin", message).expect("write message");
    fs::write("/tmp/mldsa_ctx.bin", context).expect("write context");

    println!("rust-qrllib ML-DSA-87:");
    println!("  PK size:  {} bytes", public_key.len());
    println!("  Sig size: {} bytes", signature.len());
    println!("  Context:  {}", String::from_utf8_lossy(context));
    println!("  Self-verify: PASSED");

    ExitCode::SUCCESS
}
