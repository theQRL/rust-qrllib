use std::{fs, process::ExitCode};

use qrllib::{Dilithium, verify_dilithium_signature};

fn main() -> ExitCode {
    let mut seed = [0_u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let signer = Dilithium::from_seed(seed);
    let public_key = signer.public_key_bytes();
    let message = b"Dilithium cross-implementation verification";
    let signature = match signer.sign(message) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("sign error: {error}");
            return ExitCode::FAILURE;
        }
    };

    if !verify_dilithium_signature(message, &signature, &public_key) {
        eprintln!("self-verification failed");
        return ExitCode::FAILURE;
    }

    fs::write("/tmp/dilithium_pk.bin", public_key).expect("write public key");
    fs::write("/tmp/dilithium_sig.bin", signature).expect("write signature");
    fs::write("/tmp/dilithium_msg.bin", message).expect("write message");

    println!("rust-qrllib Dilithium5:");
    println!("  PK size:  {} bytes", public_key.len());
    println!("  Sig size: {} bytes", signature.len());
    println!("  Self-verify: PASSED");

    ExitCode::SUCCESS
}
