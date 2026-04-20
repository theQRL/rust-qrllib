use qrllib::{
    Descriptor, Dilithium, LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE, LEGACY_XMSS_EXTENDED_SEED_SIZE,
    LegacyXmssWallet, MlDsa87Wallet, QrllibError, SphincsPlus256sWallet, XmssHashFunction,
    XmssHeight, sign_dilithium_with_secret_key, verify_dilithium_signature, verify_legacy_xmss,
    verify_mldsa87_wallet_signature, verify_sphincsplus_wallet_signature,
};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// Opaque registry of wallet instances held in wasm-linear memory. Each
/// registered wallet is reachable only via an integer handle that JavaScript
/// callers pass back across the wasm boundary. The registry exists so that
/// browser callers do not need to pass the raw extended seed hex on every
/// signing call; the seed crosses the boundary exactly once at
/// [`open_mldsa_wallet`] / [`open_sphincsplus_wallet`] /
/// [`open_legacy_xmss_wallet`] / [`open_dilithium_signer`] time. Calling
/// [`close_wallet`] removes the entry and runs the wallet's `Drop`, which
/// zeroizes the in-memory secret state.
enum WalletEntry {
    MlDsa87(MlDsa87Wallet),
    SphincsPlus256s(SphincsPlus256sWallet),
    LegacyXmss(LegacyXmssWallet),
    Dilithium(Dilithium),
}

thread_local! {
    static WALLET_REGISTRY: RefCell<HashMap<u32, WalletEntry>> = RefCell::new(HashMap::new());
    static NEXT_HANDLE: RefCell<u32> = const { RefCell::new(1) };
}

fn store_wallet(entry: WalletEntry) -> u32 {
    let handle = NEXT_HANDLE.with(|next| {
        let mut guard = next.borrow_mut();
        let value = *guard;
        *guard = guard.wrapping_add(1).max(1);
        value
    });
    WALLET_REGISTRY.with(|registry| registry.borrow_mut().insert(handle, entry));
    handle
}

fn with_entry<T>(handle: u32, f: impl FnOnce(&WalletEntry) -> Result<T, JsValue>) -> Result<T, JsValue> {
    WALLET_REGISTRY.with(|registry| {
        let guard = registry.borrow();
        let entry = guard.get(&handle).ok_or_else(|| JsValue::from_str("unknown wallet handle"))?;
        f(entry)
    })
}

fn with_entry_mut<T>(
    handle: u32,
    f: impl FnOnce(&mut WalletEntry) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    WALLET_REGISTRY.with(|registry| {
        let mut guard = registry.borrow_mut();
        let entry = guard.get_mut(&handle).ok_or_else(|| JsValue::from_str("unknown wallet handle"))?;
        f(entry)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletSnapshot {
    scheme: &'static str,
    address: String,
    descriptor_hex: String,
    extended_seed_hex: String,
    mnemonic: String,
    public_key_hex: String,
    raw_seed_hex: String,
    xmss_hash_function: Option<&'static str>,
    xmss_height: Option<u8>,
    xmss_index: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureSnapshot {
    scheme: &'static str,
    signature_hex: String,
    verified: bool,
    xmss_index: Option<u32>,
    xmss_next_index: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DilithiumSnapshot {
    scheme: &'static str,
    seed_hex: String,
    public_key_hex: String,
}

fn to_js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn xmss_hash_function_name(hash_function: XmssHashFunction) -> &'static str {
    match hash_function {
        XmssHashFunction::Sha2_256 => "sha2_256",
        XmssHashFunction::Shake128 => "shake128",
        XmssHashFunction::Shake256 => "shake256",
    }
}

fn parse_xmss_hash_function(value: &str) -> Result<XmssHashFunction, JsValue> {
    match value {
        "sha2_256" => Ok(XmssHashFunction::Sha2_256),
        "shake128" => Ok(XmssHashFunction::Shake128),
        "shake256" => Ok(XmssHashFunction::Shake256),
        _ => Err(JsValue::from_str(
            "invalid XMSS hash function; expected sha2_256, shake128, or shake256",
        )),
    }
}

fn decode_prefixed_hex(value: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(value.trim_start_matches("0x")).map_err(to_js_error)
}

fn snapshot_mldsa_wallet(wallet: &MlDsa87Wallet) -> Result<WalletSnapshot, JsValue> {
    Ok(WalletSnapshot {
        scheme: "ml-dsa-87",
        address: wallet.address_string(),
        descriptor_hex: hex::encode(wallet.descriptor().to_bytes()),
        extended_seed_hex: wallet.hex_seed().map_err(to_js_error)?,
        mnemonic: wallet.mnemonic().map_err(to_js_error)?,
        public_key_hex: hex::encode(wallet.public_key()),
        raw_seed_hex: wallet.seed().to_hex_prefixed(),
        xmss_hash_function: None,
        xmss_height: None,
        xmss_index: None,
    })
}

fn snapshot_xmss_wallet(wallet: &LegacyXmssWallet) -> Result<WalletSnapshot, JsValue> {
    Ok(WalletSnapshot {
        scheme: "legacy-xmss",
        address: hex::encode(wallet.address().map_err(to_js_error)?),
        descriptor_hex: hex::encode(wallet.descriptor().to_bytes()),
        extended_seed_hex: wallet.hex_seed(),
        mnemonic: wallet.mnemonic().map_err(to_js_error)?,
        public_key_hex: hex::encode(wallet.public_key()),
        raw_seed_hex: format!("0x{}", hex::encode(wallet.seed())),
        xmss_hash_function: Some(xmss_hash_function_name(wallet.descriptor().hash_function())),
        xmss_height: Some(wallet.height().as_u8()),
        xmss_index: Some(wallet.index()),
    })
}

fn snapshot_sphincs_wallet(wallet: &SphincsPlus256sWallet) -> Result<WalletSnapshot, JsValue> {
    Ok(WalletSnapshot {
        scheme: "sphincsplus-256s",
        address: wallet.address_string(),
        descriptor_hex: hex::encode(wallet.descriptor().to_bytes()),
        extended_seed_hex: wallet.hex_seed().map_err(to_js_error)?,
        mnemonic: wallet.mnemonic().map_err(to_js_error)?,
        public_key_hex: hex::encode(wallet.public_key()),
        raw_seed_hex: wallet.seed().to_hex_prefixed(),
        xmss_hash_function: None,
        xmss_height: None,
        xmss_index: None,
    })
}

fn snapshot_dilithium(signer: &Dilithium) -> DilithiumSnapshot {
    DilithiumSnapshot {
        scheme: "legacy-dilithium",
        seed_hex: signer.hex_seed(),
        public_key_hex: hex::encode(signer.public_key_bytes()),
    }
}

fn xmss_wallet_from_hex_seed(
    extended_seed_hex: &str,
    index: u32,
) -> Result<LegacyXmssWallet, JsValue> {
    let bytes = decode_prefixed_hex(extended_seed_hex)?;
    if bytes.len() != LEGACY_XMSS_EXTENDED_SEED_SIZE {
        return Err(to_js_error(QrllibError::InvalidExtendedSeedSize(
            bytes.len(),
            LEGACY_XMSS_EXTENDED_SEED_SIZE,
        )));
    }

    let mut extended_seed = [0_u8; LEGACY_XMSS_EXTENDED_SEED_SIZE];
    extended_seed.copy_from_slice(&bytes);
    let mut wallet =
        LegacyXmssWallet::new_from_extended_seed(extended_seed).map_err(to_js_error)?;
    wallet.set_index(index).map_err(to_js_error)?;
    Ok(wallet)
}

#[wasm_bindgen]
pub fn generate_wallet() -> Result<JsValue, JsValue> {
    let wallet = MlDsa87Wallet::generate().map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_mldsa_wallet(&wallet)?).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn wallet_from_extended_seed_hex(extended_seed_hex: String) -> Result<JsValue, JsValue> {
    let wallet = MlDsa87Wallet::from_hex_extended_seed(&extended_seed_hex).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_mldsa_wallet(&wallet)?).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn generate_sphincsplus_wallet() -> Result<JsValue, JsValue> {
    let wallet = SphincsPlus256sWallet::generate().map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_sphincs_wallet(&wallet)?).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn generate_dilithium_signer() -> Result<JsValue, JsValue> {
    let signer = Dilithium::generate().map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_dilithium(&signer)).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn dilithium_from_hex_seed(seed_hex: String) -> Result<JsValue, JsValue> {
    let signer = Dilithium::from_hex_seed(&seed_hex).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_dilithium(&signer)).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn sphincsplus_wallet_from_extended_seed_hex(
    extended_seed_hex: String,
) -> Result<JsValue, JsValue> {
    let wallet =
        SphincsPlus256sWallet::from_hex_extended_seed(&extended_seed_hex).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_sphincs_wallet(&wallet)?).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn sign_message(extended_seed_hex: String, message: String) -> Result<JsValue, JsValue> {
    let wallet = MlDsa87Wallet::from_hex_extended_seed(&extended_seed_hex).map_err(to_js_error)?;
    let signature = wallet.sign(message.as_bytes()).map_err(to_js_error)?;

    let payload = SignatureSnapshot {
        scheme: "ml-dsa-87",
        signature_hex: hex::encode(signature),
        verified: verify_mldsa87_wallet_signature(
            message.as_bytes(),
            &signature,
            &wallet.public_key(),
            wallet.descriptor(),
        ),
        xmss_index: None,
        xmss_next_index: None,
    };

    serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn sign_dilithium_message(seed_hex: String, message: String) -> Result<JsValue, JsValue> {
    let signer = Dilithium::from_hex_seed(&seed_hex).map_err(to_js_error)?;
    let signature =
        sign_dilithium_with_secret_key(message.as_bytes(), signer.secret_key_bytes().as_slice())
            .map_err(to_js_error)?;

    let payload = SignatureSnapshot {
        scheme: "legacy-dilithium",
        signature_hex: hex::encode(signature),
        verified: verify_dilithium_signature(
            message.as_bytes(),
            &signature,
            &signer.public_key_bytes(),
        ),
        xmss_index: None,
        xmss_next_index: None,
    };

    serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn verify_message(
    public_key_hex: String,
    descriptor_hex: String,
    message: String,
    signature_hex: String,
) -> Result<bool, JsValue> {
    let public_key = hex::decode(public_key_hex).map_err(to_js_error)?;
    let descriptor_bytes = hex::decode(descriptor_hex).map_err(to_js_error)?;
    let descriptor = Descriptor::from_bytes(&descriptor_bytes).map_err(to_js_error)?;
    let signature = hex::decode(signature_hex).map_err(to_js_error)?;

    Ok(verify_mldsa87_wallet_signature(message.as_bytes(), &signature, &public_key, descriptor))
}

#[wasm_bindgen]
pub fn verify_dilithium_message(
    public_key_hex: String,
    message: String,
    signature_hex: String,
) -> Result<bool, JsValue> {
    let public_key = decode_prefixed_hex(&public_key_hex)?;
    let signature = decode_prefixed_hex(&signature_hex)?;
    Ok(verify_dilithium_signature(message.as_bytes(), &signature, &public_key))
}

#[wasm_bindgen]
pub fn sign_sphincsplus_message(
    extended_seed_hex: String,
    message: String,
) -> Result<JsValue, JsValue> {
    let wallet =
        SphincsPlus256sWallet::from_hex_extended_seed(&extended_seed_hex).map_err(to_js_error)?;
    let signature = wallet.sign(message.as_bytes()).map_err(to_js_error)?;

    let payload = SignatureSnapshot {
        scheme: "sphincsplus-256s",
        signature_hex: hex::encode(signature),
        verified: verify_sphincsplus_wallet_signature(
            message.as_bytes(),
            &signature,
            &wallet.public_key(),
            wallet.descriptor(),
        ),
        xmss_index: None,
        xmss_next_index: None,
    };

    serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn verify_sphincsplus_message(
    public_key_hex: String,
    descriptor_hex: String,
    message: String,
    signature_hex: String,
) -> Result<bool, JsValue> {
    let public_key = hex::decode(public_key_hex).map_err(to_js_error)?;
    let descriptor_bytes = hex::decode(descriptor_hex).map_err(to_js_error)?;
    let descriptor = Descriptor::from_bytes(&descriptor_bytes).map_err(to_js_error)?;
    let signature = hex::decode(signature_hex).map_err(to_js_error)?;

    Ok(verify_sphincsplus_wallet_signature(message.as_bytes(), &signature, &public_key, descriptor))
}

#[wasm_bindgen]
pub fn generate_xmss_wallet(height: u8, hash_function: String) -> Result<JsValue, JsValue> {
    let wallet = LegacyXmssWallet::new(
        XmssHeight::new(height).map_err(to_js_error)?,
        parse_xmss_hash_function(&hash_function)?,
    )
    .map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&snapshot_xmss_wallet(&wallet)?).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn xmss_wallet_from_extended_seed_hex(
    extended_seed_hex: String,
    index: u32,
) -> Result<JsValue, JsValue> {
    let wallet = xmss_wallet_from_hex_seed(&extended_seed_hex, index)?;
    serde_wasm_bindgen::to_value(&snapshot_xmss_wallet(&wallet)?).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn sign_xmss_message(
    extended_seed_hex: String,
    index: u32,
    message: String,
) -> Result<JsValue, JsValue> {
    let mut wallet = xmss_wallet_from_hex_seed(&extended_seed_hex, index)?;
    let signature = wallet.sign(message.as_bytes()).map_err(to_js_error)?;

    let payload = SignatureSnapshot {
        scheme: "legacy-xmss",
        signature_hex: hex::encode(&signature),
        verified: verify_legacy_xmss(message.as_bytes(), &signature, wallet.public_key()),
        xmss_index: Some(index),
        xmss_next_index: Some(wallet.index()),
    };

    serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn verify_xmss_message(
    public_key_hex: String,
    message: String,
    signature_hex: String,
) -> Result<bool, JsValue> {
    let public_key = decode_prefixed_hex(&public_key_hex)?;
    if public_key.len() != LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE {
        return Err(to_js_error(QrllibError::InvalidXmssKeyLength(public_key.len())));
    }

    let signature = decode_prefixed_hex(&signature_hex)?;
    let mut extended_public_key = [0_u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE];
    extended_public_key.copy_from_slice(&public_key);

    Ok(verify_legacy_xmss(message.as_bytes(), &signature, extended_public_key))
}

// =====================================================================
// Handle-based wallet API (preferred).
//
// These entry points accept the extended seed ONCE (or generate fresh
// randomness in-wasm) and return an opaque u32 handle. Subsequent sign /
// snapshot / inspect calls take the handle, so the raw seed does not need
// to be retained on the JavaScript heap between operations. Callers should
// `close_wallet(handle)` when done; closing removes the registry entry
// and runs the wallet's `Drop`, which zeroizes the secret state.
// =====================================================================

/// Generate a fresh ML-DSA-87 wallet inside wasm and return a handle.
#[wasm_bindgen]
pub fn create_mldsa_wallet() -> Result<u32, JsValue> {
    let wallet = MlDsa87Wallet::generate().map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::MlDsa87(wallet)))
}

/// Open an ML-DSA-87 wallet from its extended-seed hex and return a handle.
#[wasm_bindgen]
pub fn open_mldsa_wallet(extended_seed_hex: String) -> Result<u32, JsValue> {
    let wallet = MlDsa87Wallet::from_hex_extended_seed(&extended_seed_hex).map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::MlDsa87(wallet)))
}

/// Generate a fresh SPHINCS+-256s wallet inside wasm and return a handle.
#[wasm_bindgen]
pub fn create_sphincsplus_wallet() -> Result<u32, JsValue> {
    let wallet = SphincsPlus256sWallet::generate().map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::SphincsPlus256s(wallet)))
}

/// Open a SPHINCS+-256s wallet from its extended-seed hex and return a handle.
#[wasm_bindgen]
pub fn open_sphincsplus_wallet(extended_seed_hex: String) -> Result<u32, JsValue> {
    let wallet =
        SphincsPlus256sWallet::from_hex_extended_seed(&extended_seed_hex).map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::SphincsPlus256s(wallet)))
}

/// Generate a fresh legacy XMSS wallet inside wasm and return a handle.
#[wasm_bindgen]
pub fn create_legacy_xmss_wallet(height: u8, hash_function: String) -> Result<u32, JsValue> {
    let wallet = LegacyXmssWallet::new(
        XmssHeight::new(height).map_err(to_js_error)?,
        parse_xmss_hash_function(&hash_function)?,
    )
    .map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::LegacyXmss(wallet)))
}

/// Open a legacy XMSS wallet from its extended seed + OTS index and return a handle.
#[wasm_bindgen]
pub fn open_legacy_xmss_wallet(
    extended_seed_hex: String,
    index: u32,
) -> Result<u32, JsValue> {
    let wallet = xmss_wallet_from_hex_seed(&extended_seed_hex, index)?;
    Ok(store_wallet(WalletEntry::LegacyXmss(wallet)))
}

/// Generate a fresh legacy Dilithium signer inside wasm and return a handle.
#[wasm_bindgen]
pub fn create_dilithium_signer() -> Result<u32, JsValue> {
    let signer = Dilithium::generate().map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::Dilithium(signer)))
}

/// Open a legacy Dilithium signer from its 32-byte hex seed and return a handle.
#[wasm_bindgen]
pub fn open_dilithium_signer(seed_hex: String) -> Result<u32, JsValue> {
    let signer = Dilithium::from_hex_seed(&seed_hex).map_err(to_js_error)?;
    Ok(store_wallet(WalletEntry::Dilithium(signer)))
}

/// Return the snapshot JSON for the wallet behind `handle`.
#[wasm_bindgen]
pub fn wallet_snapshot(handle: u32) -> Result<JsValue, JsValue> {
    with_entry(handle, |entry| match entry {
        WalletEntry::MlDsa87(wallet) => {
            serde_wasm_bindgen::to_value(&snapshot_mldsa_wallet(wallet)?).map_err(to_js_error)
        }
        WalletEntry::SphincsPlus256s(wallet) => {
            serde_wasm_bindgen::to_value(&snapshot_sphincs_wallet(wallet)?).map_err(to_js_error)
        }
        WalletEntry::LegacyXmss(wallet) => {
            serde_wasm_bindgen::to_value(&snapshot_xmss_wallet(wallet)?).map_err(to_js_error)
        }
        WalletEntry::Dilithium(signer) => {
            serde_wasm_bindgen::to_value(&snapshot_dilithium(signer)).map_err(to_js_error)
        }
    })
}

/// Sign `message` with the wallet behind `handle`. For stateful XMSS wallets
/// this advances the OTS index; for stateless schemes it is side-effect-free
/// on the wallet.
#[wasm_bindgen]
pub fn wallet_sign(handle: u32, message: String) -> Result<JsValue, JsValue> {
    with_entry_mut(handle, |entry| match entry {
        WalletEntry::MlDsa87(wallet) => {
            let signature = wallet.sign(message.as_bytes()).map_err(to_js_error)?;
            let payload = SignatureSnapshot {
                scheme: "ml-dsa-87",
                signature_hex: hex::encode(signature),
                verified: verify_mldsa87_wallet_signature(
                    message.as_bytes(),
                    &signature,
                    &wallet.public_key(),
                    wallet.descriptor(),
                ),
                xmss_index: None,
                xmss_next_index: None,
            };
            serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
        }
        WalletEntry::SphincsPlus256s(wallet) => {
            let signature = wallet.sign(message.as_bytes()).map_err(to_js_error)?;
            let payload = SignatureSnapshot {
                scheme: "sphincsplus-256s",
                signature_hex: hex::encode(signature),
                verified: verify_sphincsplus_wallet_signature(
                    message.as_bytes(),
                    &signature,
                    &wallet.public_key(),
                    wallet.descriptor(),
                ),
                xmss_index: None,
                xmss_next_index: None,
            };
            serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
        }
        WalletEntry::LegacyXmss(wallet) => {
            let current_index = wallet.index();
            let signature = wallet.sign(message.as_bytes()).map_err(to_js_error)?;
            let payload = SignatureSnapshot {
                scheme: "legacy-xmss",
                signature_hex: hex::encode(&signature),
                verified: verify_legacy_xmss(message.as_bytes(), &signature, wallet.public_key()),
                xmss_index: Some(current_index),
                xmss_next_index: Some(wallet.index()),
            };
            serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
        }
        WalletEntry::Dilithium(signer) => {
            let signature = sign_dilithium_with_secret_key(
                message.as_bytes(),
                signer.secret_key_bytes().as_slice(),
            )
            .map_err(to_js_error)?;
            let payload = SignatureSnapshot {
                scheme: "legacy-dilithium",
                signature_hex: hex::encode(signature),
                verified: verify_dilithium_signature(
                    message.as_bytes(),
                    &signature,
                    &signer.public_key_bytes(),
                ),
                xmss_index: None,
                xmss_next_index: None,
            };
            serde_wasm_bindgen::to_value(&payload).map_err(to_js_error)
        }
    })
}

/// Remove the registry entry for `handle`. The wallet's `Drop` runs, which
/// zeroizes the in-memory secret state.
#[wasm_bindgen]
pub fn close_wallet(handle: u32) -> Result<(), JsValue> {
    let removed = WALLET_REGISTRY.with(|registry| registry.borrow_mut().remove(&handle));
    if removed.is_some() {
        Ok(())
    } else {
        Err(JsValue::from_str("unknown wallet handle"))
    }
}

/// Close every registered wallet. Intended for browser-page teardown.
#[wasm_bindgen]
pub fn close_all_wallets() {
    WALLET_REGISTRY.with(|registry| registry.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    //! Native-target smoke tests for the handle registry plumbing. These do
    //! not exercise the `#[wasm_bindgen]` attributes end-to-end (that would
    //! require `wasm-bindgen-test` and a browser harness); they do cover the
    //! pure-Rust lifecycle that sits behind every handle-based entry point:
    //! create → store → retrieve → remove → drop.

    use super::{WalletEntry, WALLET_REGISTRY, store_wallet};
    use qrllib::{MlDsa87Wallet, Seed};

    fn seed(byte: u8) -> Seed {
        Seed::from_bytes(&[byte; qrllib::SEED_SIZE]).expect("seed")
    }

    fn registry_len() -> usize {
        WALLET_REGISTRY.with(|registry| registry.borrow().len())
    }

    #[test]
    fn registry_round_trip_inserts_and_removes_entries() {
        // Start from a known state — other tests in the same process may have
        // populated the registry; we track deltas, not absolutes.
        let baseline = registry_len();

        let wallet = MlDsa87Wallet::from_seed(seed(51)).expect("wallet");
        let expected_pk = wallet.public_key();
        let handle = store_wallet(WalletEntry::MlDsa87(wallet));
        assert_eq!(registry_len(), baseline + 1);

        let observed_pk = WALLET_REGISTRY.with(|registry| {
            let guard = registry.borrow();
            match guard.get(&handle).expect("handle present") {
                WalletEntry::MlDsa87(wallet) => wallet.public_key(),
                _ => panic!("wrong entry variant"),
            }
        });
        assert_eq!(expected_pk, observed_pk);

        let removed = WALLET_REGISTRY.with(|registry| registry.borrow_mut().remove(&handle));
        assert!(removed.is_some(), "remove must find the handle that was stored");
        assert_eq!(registry_len(), baseline, "removal must restore the baseline count");

        // Double-remove is a no-op returning None.
        let removed_again = WALLET_REGISTRY.with(|registry| registry.borrow_mut().remove(&handle));
        assert!(removed_again.is_none());
    }

    #[test]
    fn handle_allocator_never_issues_the_reserved_zero() {
        // `store_wallet`'s post-increment skips zero after wrap (`.max(1)`).
        // Exercise a few allocations and make sure none is zero.
        for _ in 0..8 {
            let handle = store_wallet(WalletEntry::MlDsa87(
                MlDsa87Wallet::from_seed(seed(61)).expect("wallet"),
            ));
            assert_ne!(handle, 0);
            WALLET_REGISTRY.with(|registry| registry.borrow_mut().remove(&handle));
        }
    }
}
