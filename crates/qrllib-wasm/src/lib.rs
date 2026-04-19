use qrllib::{
    Descriptor, Dilithium, LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE, LEGACY_XMSS_EXTENDED_SEED_SIZE,
    LegacyXmssWallet, MlDsa87Wallet, QrllibError, SphincsPlus256sWallet, XmssHashFunction,
    XmssHeight, sign_dilithium_with_secret_key, verify_dilithium_signature, verify_legacy_xmss,
    verify_mldsa87_wallet_signature, verify_sphincsplus_wallet_signature,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

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
    let signature = sign_dilithium_with_secret_key(message.as_bytes(), &signer.secret_key_bytes())
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
