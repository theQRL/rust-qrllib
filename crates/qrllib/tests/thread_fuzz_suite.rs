use std::{sync::Arc, thread};

use qrllib::{
    DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SIGNATURE_SIZE, Dilithium, ML_DSA_87_PUBLIC_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE, MlDsa87, SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE,
    SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s, Xmss,
    XmssHashFunction, XmssHeight, dilithium_extract_message, dilithium_extract_signature,
    dilithium_open, extract_message, extract_signature, mldsa::verify_bytes, open,
    sphincsplus_extract_message, sphincsplus_extract_signature, sphincsplus_open,
    verify_dilithium_signature, verify_sphincsplus_signature, verify_xmss,
    verify_xmss_with_custom_wots_param_w,
};

fn pad_array<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut output = [0_u8; N];
    let len = input.len().min(N);
    output[..len].copy_from_slice(&input[..len]);
    output
}

#[test]
fn stateless_signature_schemes_are_safe_for_parallel_read_only_and_signing_paths() {
    let dilithium = Arc::new(Dilithium::from_seed([7_u8; 32]));
    let dilithium_message = b"concurrent dilithium verification".to_vec();
    let dilithium_signature = dilithium.sign(&dilithium_message).expect("dilithium signature");
    let mut dilithium_sealed = dilithium_signature.to_vec();
    dilithium_sealed.extend_from_slice(&dilithium_message);
    let dilithium_public_key = dilithium.public_key_bytes();

    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..4 {
            let signer = Arc::clone(&dilithium);
            let message = dilithium_message.clone();
            let signature = dilithium_signature;
            let sealed = dilithium_sealed.clone();
            handles.push(scope.spawn(move || {
                assert!(verify_dilithium_signature(&message, &signature, &dilithium_public_key));
                assert_eq!(
                    dilithium_open(&sealed, &dilithium_public_key).expect("opened"),
                    message
                );
                assert_eq!(
                    dilithium_extract_signature(&sealed).expect("signature slice").len(),
                    DILITHIUM_SIGNATURE_SIZE
                );
                assert!(dilithium_extract_message(&sealed).is_some());
                signer.sign(&message).expect("parallel sign")
            }));
        }

        let first = handles.remove(0).join().expect("thread join");
        for handle in handles {
            assert_eq!(handle.join().expect("thread join"), first);
        }
    });

    let mldsa = Arc::new(MlDsa87::from_seed([9_u8; 32]));
    let mldsa_context = b"context".to_vec();
    let mldsa_message = b"concurrent mldsa verification".to_vec();
    let mldsa_signature = mldsa.sign(&mldsa_context, &mldsa_message).expect("mldsa signature");
    let mut mldsa_sealed = mldsa_signature.to_vec();
    mldsa_sealed.extend_from_slice(&mldsa_message);
    let mldsa_public_key = mldsa.public_key_bytes();

    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..4 {
            let signer = Arc::clone(&mldsa);
            let context = mldsa_context.clone();
            let message = mldsa_message.clone();
            let signature = mldsa_signature;
            let sealed = mldsa_sealed.clone();
            handles.push(scope.spawn(move || {
                assert!(
                    verify_bytes(&context, &message, &signature, &mldsa_public_key)
                        .expect("verify")
                );
                assert_eq!(
                    open(&context, &sealed, &mldsa_public_key).expect("open").expect("opened"),
                    message
                );
                assert_eq!(
                    extract_signature(&sealed).expect("signature slice").len(),
                    ML_DSA_87_SIGNATURE_SIZE
                );
                assert!(extract_message(&sealed).is_some());
                signer.sign(&context, &message).expect("parallel sign")
            }));
        }

        for handle in handles {
            let signature = handle.join().expect("thread join");
            assert!(
                verify_bytes(&mldsa_context, &mldsa_message, &signature, &mldsa_public_key)
                    .expect("verify"),
            );
        }
    });

    let sphincs_seed = {
        let mut seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        seed
    };
    let sphincs = Arc::new(SphincsPlus256s::from_seed(sphincs_seed));
    let sphincs_message = b"parallel sphincs verification".to_vec();
    let sphincs_signature = sphincs.sign(&sphincs_message).expect("sphincs signature");
    let mut sphincs_sealed = sphincs_signature.to_vec();
    sphincs_sealed.extend_from_slice(&sphincs_message);
    let sphincs_public_key = sphincs.public_key_bytes();

    thread::scope(|scope| {
        let mut verify_handles = Vec::new();
        for _ in 0..2 {
            let message = sphincs_message.clone();
            let signature = sphincs_signature;
            let sealed = sphincs_sealed.clone();
            verify_handles.push(scope.spawn(move || {
                assert!(verify_sphincsplus_signature(&message, &signature, &sphincs_public_key));
                assert_eq!(
                    sphincsplus_open(&sealed, &sphincs_public_key).expect("opened"),
                    message
                );
                assert_eq!(
                    sphincsplus_extract_signature(&sealed).expect("signature slice").len(),
                    SPHINCS_PLUS_256S_SIGNATURE_SIZE
                );
                assert!(sphincsplus_extract_message(&sealed).is_some());
            }));
        }

        for handle in verify_handles {
            handle.join().expect("thread join");
        }
    });

    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..2 {
            handles.push(
                scope.spawn(move || SphincsPlus256s::from_seed(sphincs_seed).public_key_bytes()),
            );
        }

        let first = handles.remove(0).join().expect("thread join");
        for handle in handles {
            assert_eq!(handle.join().expect("thread join"), first);
        }
    });
}

#[test]
fn xmss_thread_safety_matches_stateful_contract() {
    let height = XmssHeight::new(4).expect("height");
    let mut signer =
        Xmss::initialize_tree(height, XmssHashFunction::Shake128, &[0_u8; 48]).expect("tree");
    let public_key = signer.public_key();
    let message = b"xmss concurrent verification".to_vec();
    let signature = signer.sign(&message).expect("signature");

    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let message = message.clone();
            let signature = signature.clone();
            handles.push(scope.spawn(move || {
                assert!(verify_xmss(XmssHashFunction::Shake128, &message, &signature, &public_key));
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }
    });

    let mut sequential_signer =
        Xmss::initialize_tree(height, XmssHashFunction::Shake128, &[3_u8; 48]).expect("tree");
    let sequential_public_key = sequential_signer.public_key();
    for expected_index in 1..=6 {
        let message = format!("message-{expected_index}");
        let signature = sequential_signer.sign(message.as_bytes()).expect("signature");
        assert_eq!(sequential_signer.index(), expected_index);
        assert!(verify_xmss(
            XmssHashFunction::Shake128,
            message.as_bytes(),
            &signature,
            &sequential_public_key
        ));
    }

    thread::scope(|scope| {
        let mut handles = Vec::new();
        for seed_byte in [11_u8, 22, 33, 44] {
            handles.push(scope.spawn(move || {
                let seed = [seed_byte; 48];
                let mut signer =
                    Xmss::initialize_tree(height, XmssHashFunction::Shake256, &seed).expect("tree");
                let message = vec![seed_byte; 12];
                let signature = signer.sign(&message).expect("signature");
                assert!(verify_xmss(
                    XmssHashFunction::Shake256,
                    &message,
                    &signature,
                    &signer.public_key()
                ));
                signer.root()
            }));
        }

        let mut roots = Vec::new();
        for handle in handles {
            roots.push(handle.join().expect("thread join"));
        }
        roots.sort();
        roots.dedup();
        assert_eq!(roots.len(), 4);
    });
}

#[test]
fn go_fuzz_seed_corpora_do_not_panic_in_rust() {
    let dilithium_verify_corpus = [
        (Vec::new(), vec![0_u8; DILITHIUM_SIGNATURE_SIZE], vec![0_u8; DILITHIUM_PUBLIC_KEY_SIZE]),
        (
            vec![0_u8; 32],
            vec![0_u8; DILITHIUM_SIGNATURE_SIZE],
            vec![0_u8; DILITHIUM_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; 1000],
            vec![0_u8; DILITHIUM_SIGNATURE_SIZE],
            vec![0_u8; DILITHIUM_PUBLIC_KEY_SIZE],
        ),
    ];
    for (message, sig_bytes, pk_bytes) in dilithium_verify_corpus {
        let signature = pad_array::<DILITHIUM_SIGNATURE_SIZE>(&sig_bytes);
        let public_key = pad_array::<DILITHIUM_PUBLIC_KEY_SIZE>(&pk_bytes);
        let _ = verify_dilithium_signature(&message, &signature, &public_key);
    }
    for (signature_message, pk_bytes) in [
        (Vec::new(), vec![0_u8; DILITHIUM_PUBLIC_KEY_SIZE]),
        (vec![0_u8; DILITHIUM_SIGNATURE_SIZE], vec![0_u8; DILITHIUM_PUBLIC_KEY_SIZE]),
        (vec![0_u8; DILITHIUM_SIGNATURE_SIZE + 100], vec![0_u8; DILITHIUM_PUBLIC_KEY_SIZE]),
    ] {
        let public_key = pad_array::<DILITHIUM_PUBLIC_KEY_SIZE>(&pk_bytes);
        let _ = dilithium_open(&signature_message, &public_key);
    }
    for len in
        [0, DILITHIUM_SIGNATURE_SIZE - 1, DILITHIUM_SIGNATURE_SIZE, DILITHIUM_SIGNATURE_SIZE + 100]
    {
        let input = vec![0_u8; len];
        let _ = dilithium_extract_message(&input);
        let _ = dilithium_extract_signature(&input);
    }

    let mldsa_verify_corpus = [
        (
            Vec::new(),
            Vec::new(),
            vec![0_u8; ML_DSA_87_SIGNATURE_SIZE],
            vec![0_u8; ML_DSA_87_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; 10],
            vec![0_u8; 32],
            vec![0_u8; ML_DSA_87_SIGNATURE_SIZE],
            vec![0_u8; ML_DSA_87_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; 255],
            vec![0_u8; 1000],
            vec![0_u8; ML_DSA_87_SIGNATURE_SIZE],
            vec![0_u8; ML_DSA_87_PUBLIC_KEY_SIZE],
        ),
    ];
    for (context, message, sig_bytes, pk_bytes) in mldsa_verify_corpus {
        let signature = pad_array::<ML_DSA_87_SIGNATURE_SIZE>(&sig_bytes);
        let public_key = pad_array::<ML_DSA_87_PUBLIC_KEY_SIZE>(&pk_bytes);
        let _ = verify_bytes(&context, &message, &signature, &public_key);
    }
    for (context, signature_message, pk_bytes) in [
        (Vec::new(), Vec::new(), vec![0_u8; ML_DSA_87_PUBLIC_KEY_SIZE]),
        (
            vec![0_u8; 10],
            vec![0_u8; ML_DSA_87_SIGNATURE_SIZE],
            vec![0_u8; ML_DSA_87_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; 255],
            vec![0_u8; ML_DSA_87_SIGNATURE_SIZE + 100],
            vec![0_u8; ML_DSA_87_PUBLIC_KEY_SIZE],
        ),
    ] {
        let public_key = pad_array::<ML_DSA_87_PUBLIC_KEY_SIZE>(&pk_bytes);
        let _ = open(&context, &signature_message, &public_key);
    }
    for len in
        [0, ML_DSA_87_SIGNATURE_SIZE - 1, ML_DSA_87_SIGNATURE_SIZE, ML_DSA_87_SIGNATURE_SIZE + 100]
    {
        let input = vec![0_u8; len];
        let _ = extract_message(&input);
        let _ = extract_signature(&input);
    }

    let sphincs_verify_corpus = [
        (
            Vec::new(),
            vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE],
            vec![0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; 32],
            vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE],
            vec![0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; 1000],
            vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE],
            vec![0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
        ),
    ];
    for (message, sig_bytes, pk_bytes) in sphincs_verify_corpus {
        let signature = pad_array::<SPHINCS_PLUS_256S_SIGNATURE_SIZE>(&sig_bytes);
        let public_key = pad_array::<SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE>(&pk_bytes);
        let _ = verify_sphincsplus_signature(&message, &signature, &public_key);
    }
    for (signature_message, pk_bytes) in [
        (Vec::new(), vec![0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE]),
        (
            vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE],
            vec![0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
        ),
        (
            vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE + 100],
            vec![0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
        ),
    ] {
        let public_key = pad_array::<SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE>(&pk_bytes);
        let _ = sphincsplus_open(&signature_message, &public_key);
    }
    for len in [
        0,
        SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1,
        SPHINCS_PLUS_256S_SIGNATURE_SIZE,
        SPHINCS_PLUS_256S_SIGNATURE_SIZE + 100,
    ] {
        let input = vec![0_u8; len];
        let _ = sphincsplus_extract_message(&input);
        let _ = sphincsplus_extract_signature(&input);
    }

    let hash_functions =
        [XmssHashFunction::Sha2_256, XmssHashFunction::Shake128, XmssHashFunction::Shake256];
    for (message, signature, public_key, hash_function_index) in [
        (Vec::new(), Vec::new(), Vec::new(), 0_usize),
        (vec![0_u8; 32], vec![0_u8; 2287], vec![0_u8; 64], 1_usize),
        (vec![0_u8; 100], vec![0_u8; 100], vec![0_u8; 100], 2_usize),
    ] {
        let hash_function = hash_functions[hash_function_index % hash_functions.len()];
        let _ = verify_xmss(hash_function, &message, &signature, &public_key);
    }
    for (message, signature, public_key, hash_function_index, wots_param_w) in [
        (Vec::new(), Vec::new(), Vec::new(), 0_usize, 4_u32),
        (vec![0_u8; 32], vec![0_u8; 2287], vec![0_u8; 64], 1_usize, 16_u32),
        (vec![0_u8; 100], vec![0_u8; 100], vec![0_u8; 100], 2_usize, 256_u32),
    ] {
        let hash_function = hash_functions[hash_function_index % hash_functions.len()];
        let _ = verify_xmss_with_custom_wots_param_w(
            hash_function,
            &message,
            &signature,
            &public_key,
            wots_param_w,
        );
    }
}
