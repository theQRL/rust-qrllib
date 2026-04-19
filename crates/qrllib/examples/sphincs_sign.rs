use std::{fs, process::ExitCode};

use qrllib::{SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SphincsPlus256s, verify_sphincsplus_signature};

fn main() -> ExitCode {
    let mut seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let signer = SphincsPlus256s::from_seed(seed);
    let public_key = signer.public_key_bytes();
    let message = b"SPHINCS+ cross-implementation verification";
    let signature = match signer.sign(message) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("sign error: {error}");
            return ExitCode::FAILURE;
        }
    };

    if !verify_sphincsplus_signature(message, &signature, &public_key) {
        eprintln!("self-verification failed");
        return ExitCode::FAILURE;
    }

    fs::write("/tmp/sphincs_pk.bin", public_key).expect("write public key");
    fs::write("/tmp/sphincs_sig.bin", signature).expect("write signature");
    fs::write("/tmp/sphincs_msg.bin", message).expect("write message");
    fs::write("/tmp/sphincs_seed.bin", seed).expect("write seed");

    println!("rust-qrllib SPHINCS+ SHAKE-256s-robust:");
    println!("  PK size:   {} bytes", public_key.len());
    println!("  SK size:   {} bytes", signer.secret_key_bytes().len());
    println!("  Sig size:  {} bytes", signature.len());
    println!("  Seed size: {} bytes", seed.len());
    println!("  Self-verify: PASSED");

    ExitCode::SUCCESS
}
