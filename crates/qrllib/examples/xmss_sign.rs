use std::{fs, process::ExitCode};

use qrllib::{XMSS_SEED_SIZE, Xmss, XmssHashFunction, XmssHeight, verify_xmss};

const OFFSET_SK_SEED: usize = 4;
const OFFSET_SK_PRF: usize = OFFSET_SK_SEED + 32;
const OFFSET_PUB_SEED: usize = OFFSET_SK_PRF + 32;

fn main() -> ExitCode {
    let mut seed = [0_u8; XMSS_SEED_SIZE];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let height = match XmssHeight::new(10) {
        Ok(height) => height,
        Err(error) => {
            eprintln!("height error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut tree = match Xmss::initialize_tree(height, XmssHashFunction::Sha2_256, &seed) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("initialize error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let message = b"XMSS cross-implementation verification";
    let signature = match tree.sign(message) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("sign error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let public_key = tree.public_key();

    if !verify_xmss(XmssHashFunction::Sha2_256, message, &signature, &public_key) {
        eprintln!("self-verification failed");
        return ExitCode::FAILURE;
    }

    let secret_key = tree.secret_key();
    fs::write("/tmp/xmss_pk.bin", public_key).expect("write public key");
    fs::write("/tmp/xmss_sig.bin", &signature).expect("write signature");
    fs::write("/tmp/xmss_msg.bin", message).expect("write message");
    fs::write("/tmp/xmss_seed.bin", seed).expect("write seed");
    fs::write("/tmp/xmss_sk_seed.bin", &secret_key[OFFSET_SK_SEED..OFFSET_SK_PRF])
        .expect("write sk seed");
    fs::write("/tmp/xmss_sk_prf.bin", &secret_key[OFFSET_SK_PRF..OFFSET_PUB_SEED])
        .expect("write sk prf");
    fs::write("/tmp/xmss_pub_seed.bin", tree.public_seed()).expect("write pub seed");

    println!("rust-qrllib XMSS-SHA2_10_256:");
    println!("  PK size:   {} bytes", public_key.len());
    println!("  Sig size:  {} bytes", signature.len());
    println!("  Seed size: {} bytes", seed.len());
    println!("  Height:    {}", tree.height());
    println!("  Index:     {}", tree.index());
    println!("  Self-verify: PASSED");

    ExitCode::SUCCESS
}
