use crate::error::{QrllibError, Result};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::{Zeroize, Zeroizing};

/// RFC 8391 reference-implementation interop sub-module. See its
/// module doc for the bidirectional cross-verify story
/// (TOB-QRLLIB-1 part 2).
pub mod rfc8391;

const OFFSET_IDX: usize = 0;
const OFFSET_SK_SEED: usize = OFFSET_IDX + 4;
const OFFSET_SK_PRF: usize = OFFSET_SK_SEED + 32;
const OFFSET_PUB_SEED: usize = OFFSET_SK_PRF + 32;
const OFFSET_ROOT: usize = OFFSET_PUB_SEED + 32;

pub const XMSS_SECRET_KEY_SIZE: usize = 132;
pub const XMSS_PUBLIC_KEY_SIZE: usize = 64;
pub const XMSS_SEED_SIZE: usize = 48;
pub const XMSS_MAX_HEIGHT: u8 = 30;
pub const XMSS_WOTS_PARAM_K: u32 = 2;
pub const XMSS_WOTS_PARAM_W: u32 = 16;
pub const XMSS_WOTS_PARAM_N: u32 = 32;

/// Hash-function selector for the XMSS construction.
///
/// QRL's XMSS implementation **predates RFC 8391** (which standardised
/// XMSS in August 2018) and is retained here as a v1 → v2 migration
/// vehicle rather than as a standards-tracking XMSS implementation.
/// The supported values reflect QRL's pre-standardisation choices; only
/// `Sha2_256` and `Shake256` overlap with parameter sets published in
/// RFC 8391 / NIST SP 800-208. See `SECURITY.md` for the full
/// parameter-set provenance discussion (TOB-QRLLIB-7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum XmssHashFunction {
    /// XMSS-SHA2_*_256 family — signature format matches RFC 8391
    /// (August 2018). Note that the `expand_seed` construction here
    /// follows the original RFC 8391 form, not the NIST SP 800-208
    /// (October 2020) refinement; see `SECURITY.md` "Standards
    /// alignment" for the rationale.
    Sha2_256 = 0,

    /// **QRL-specific extension, retained for legacy address
    /// compatibility from QRL's pre-standardisation XMSS
    /// implementation.** Not part of RFC 8391 or NIST SP 800-208.
    /// With a 32-byte output it offers approximately 64-bit quantum
    /// security under a Grover-style attack — theoretically reduced
    /// relative to `Shake256` / `Sha2_256` (~128-bit quantum),
    /// although the gap remains difficult to exploit in practice
    /// today. **Not recommended for new wallets.** Existing v1
    /// mainnet addresses minted under SHAKE_128 must continue to be
    /// parseable, verifiable and signable, which is the only reason
    /// this option survives. New issuance on QRL is moving to
    /// ML-DSA-87 (FIPS 204). (TOB-QRLLIB-7.)
    Shake128 = 1,

    /// XMSS-SHAKE_*_256 family — signature format matches RFC 8391
    /// (August 2018). Same `expand_seed`-vs-SP-800-208 caveat as
    /// [`Sha2_256`]; see `SECURITY.md` "Standards alignment".
    Shake256 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct XmssHeight(u8);

#[derive(Clone, Debug)]
struct WotsParams {
    len1: u32,
    len2: u32,
    len: u32,
    n: u32,
    w: u32,
    log_w: u32,
    key_size: u32,
}

#[derive(Clone, Debug)]
struct XmssParams {
    wots_params: WotsParams,
    n: u32,
    h: u32,
    k: u32,
}

#[derive(Clone, Debug)]
struct TreeHashInst {
    h: u32,
    next_idx: u32,
    stack_usage: u32,
    completed: bool,
    node: Vec<u8>,
}

#[derive(Clone, Debug)]
struct BdsState {
    stack: Vec<u8>,
    stack_offset: usize,
    stack_levels: Vec<u32>,
    auth: Vec<u8>,
    keep: Vec<u8>,
    tree_hash: Vec<TreeHashInst>,
    retain: Vec<u8>,
}

/// A stateful RFC 8391 XMSS signer.
///
/// # XMSS statefulness — must read
///
/// XMSS is a **stateful** one-time-signature scheme. Signing with the same OTS
/// index twice under different messages lets any observer forge signatures on
/// (most) messages under the same public key — an irreversible compromise of
/// the entire tree.
///
/// This type deliberately does **not** implement [`Clone`]. Duplicating the
/// signer would produce two independent instances sharing the OTS index, and
/// the first pair of sign calls across them would constitute immediate
/// one-time-key reuse. Callers who need to persist and restore XMSS state (via
/// [`Xmss::secret_key`] / [`Xmss::initialize_tree`] or equivalent) own the
/// responsibility for:
///
/// - never restoring from a backup without reconciling the highest used OTS
///   index;
/// - persisting the updated index atomically, before a signature is broadcast
///   or otherwise used;
/// - serialising access so that no two threads or processes sign concurrently
///   from the same tree;
/// - rotating keys well before the tree is exhausted.
///
/// See `SECURITY.md` for the full threat model.
#[derive(Debug)]
pub struct Xmss {
    xmss_params: XmssParams,
    hash_function: XmssHashFunction,
    height: XmssHeight,
    seed: Vec<u8>,
    sk: Vec<u8>,
    bds_state: BdsState,
}

impl TryFrom<u8> for XmssHashFunction {
    type Error = QrllibError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Sha2_256),
            1 => Ok(Self::Shake128),
            2 => Ok(Self::Shake256),
            _ => Err(QrllibError::InvalidXmssHashFunction(value)),
        }
    }
}

impl core::fmt::Display for XmssHashFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sha2_256 => f.write_str("SHA2_256"),
            Self::Shake128 => f.write_str("SHAKE_128"),
            Self::Shake256 => f.write_str("SHAKE_256"),
        }
    }
}

impl XmssHeight {
    pub fn new(value: u8) -> Result<Self> {
        let height = Self(value);
        if height.is_valid() { Ok(height) } else { Err(QrllibError::InvalidXmssHeight(value)) }
    }

    pub fn from_u32(value: u32) -> Result<Self> {
        if value > u32::from(XMSS_MAX_HEIGHT) {
            return Err(QrllibError::InvalidXmssHeight(value as u8));
        }
        Self::new(value as u8)
    }

    pub fn from_descriptor_byte(value: u8) -> Result<Self> {
        Self::new((value & 0x0f) << 1)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }

    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }

    pub fn descriptor_byte(self) -> Result<u8> {
        if !self.is_valid() {
            return Err(QrllibError::InvalidXmssHeight(self.0));
        }
        Ok((self.0 >> 1) & 0x0f)
    }

    pub fn is_valid(self) -> bool {
        self.0 >= 2 && self.0 <= XMSS_MAX_HEIGHT && self.0.is_multiple_of(2)
    }
}

impl core::fmt::Display for XmssHeight {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Xmss {
    pub fn initialize_tree(
        height: XmssHeight,
        hash_function: XmssHashFunction,
        seed: &[u8],
    ) -> Result<Self> {
        let height_u32 = height.as_u32();
        // Coverage: `XmssHeight` only admits even values in [2, XMSS_MAX_HEIGHT]
        // and XMSS_WOTS_PARAM_K is the compile-time constant 2, so this guard
        // never fires for any constructible height. Kept to assert BDS-state
        // pre-conditions for auditors reading the function in isolation.
        if XMSS_WOTS_PARAM_K >= height_u32 || (height_u32 - XMSS_WOTS_PARAM_K) % 2 == 1 {
            return Err(QrllibError::InvalidXmssBdsParams);
        }

        // Reject seeds that are not exactly XMSS_SEED_SIZE (48) bytes — the
        // SHAKE256 expansion in `xmss_fast_gen_key_pair` would silently stretch
        // any length into a working tree carrying less entropy than the caller
        // believes. Mirrors go-qrllib's `InitializeTree` boundary check.
        if seed.len() != XMSS_SEED_SIZE {
            return Err(QrllibError::InvalidSeedSize(seed.len(), XMSS_SEED_SIZE));
        }

        let xmss_params =
            XmssParams::new(XMSS_WOTS_PARAM_N, height_u32, XMSS_WOTS_PARAM_W, XMSS_WOTS_PARAM_K)?;
        let mut bds_state = BdsState::new(height_u32, XMSS_WOTS_PARAM_N, XMSS_WOTS_PARAM_K);
        let mut pk = vec![0_u8; XMSS_PUBLIC_KEY_SIZE];
        let mut sk = vec![0_u8; XMSS_SECRET_KEY_SIZE];
        // Coverage: the `?` error-propagation arm is unreachable because every
        // validated `XmssHeight` / `XmssHashFunction` / seed combination produces
        // a successful keypair. Kept to surface internal invariant violations.
        xmss_fast_gen_key_pair(
            hash_function,
            &xmss_params,
            &mut pk,
            &mut sk,
            &mut bds_state,
            seed,
        )?;

        Ok(Self { xmss_params, hash_function, height, seed: seed.to_vec(), sk, bds_state })
    }

    /// Initialise an XMSS tree from 96 bytes of **already-expanded**
    /// seed material (`SK_SEED || SK_PRF || PUB_SEED`), bypassing the
    /// QRL-specific SHAKE-256 expansion that [`Xmss::initialize_tree`]
    /// applies to a 48-byte seed.
    ///
    /// This matches the layout the RFC 8391 reference implementation
    /// consumes directly, and is what the [`crate::xmss::rfc8391`]
    /// interop module uses to provide bidirectional cross-verify with
    /// the reference. QRL wallet code should use
    /// [`Xmss::initialize_tree`] instead — the 48-byte seed expansion
    /// is the only path that produces v1 mainnet addresses.
    ///
    /// (TOB-QRLLIB-1 part 2 — Rust-port parity with the Go-side
    /// `xmss.InitializeTreeFromExpandedSeed`.)
    pub fn initialize_tree_from_expanded_seed(
        height: XmssHeight,
        hash_function: XmssHashFunction,
        expanded_seed: &[u8; 96],
    ) -> Result<Self> {
        let height_u32 = height.as_u32();
        if XMSS_WOTS_PARAM_K >= height_u32 || (height_u32 - XMSS_WOTS_PARAM_K) % 2 == 1 {
            return Err(QrllibError::InvalidXmssBdsParams);
        }

        let xmss_params =
            XmssParams::new(XMSS_WOTS_PARAM_N, height_u32, XMSS_WOTS_PARAM_W, XMSS_WOTS_PARAM_K)?;
        let mut bds_state = BdsState::new(height_u32, XMSS_WOTS_PARAM_N, XMSS_WOTS_PARAM_K);
        let mut pk = vec![0_u8; XMSS_PUBLIC_KEY_SIZE];
        let mut sk = vec![0_u8; XMSS_SECRET_KEY_SIZE];
        xmss_fast_gen_key_pair_from_expanded_seed(
            hash_function,
            &xmss_params,
            &mut pk,
            &mut sk,
            &mut bds_state,
            expanded_seed,
        )?;

        // The struct's `seed` field stores the 96-byte expanded seed
        // (the input to the keypair-derivation core); QRL `initialize_tree`
        // would have stored the 48-byte caller-supplied seed instead.
        // Either way, `seed()` round-trips for the consumer.
        Ok(Self { xmss_params, hash_function, height, seed: expanded_seed.to_vec(), sk, bds_state })
    }

    /// Returns a zeroizing copy of the XMSS seed. The returned value
    /// drops-clear on scope exit.
    pub fn seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.seed.clone())
    }

    /// Returns a zeroizing copy of the 132-byte XMSS secret key (including the
    /// advancing OTS index in the first four bytes).
    pub fn secret_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.sk.clone())
    }

    pub fn public_seed(&self) -> Vec<u8> {
        self.sk[OFFSET_PUB_SEED..OFFSET_PUB_SEED + 32].to_vec()
    }

    pub fn root(&self) -> Vec<u8> {
        self.sk[OFFSET_ROOT..OFFSET_ROOT + 32].to_vec()
    }

    pub fn public_key(&self) -> [u8; XMSS_PUBLIC_KEY_SIZE] {
        let root = self.root();
        let public_seed = self.public_seed();
        let mut output = [0_u8; XMSS_PUBLIC_KEY_SIZE];
        output[..32].copy_from_slice(&root);
        output[32..].copy_from_slice(&public_seed);
        output
    }

    pub fn hash_function(&self) -> XmssHashFunction {
        self.hash_function
    }

    pub fn height(&self) -> XmssHeight {
        self.height
    }

    pub fn index(&self) -> u32 {
        read_index(&self.sk)
    }

    pub fn set_index(&mut self, new_index: u32) -> Result<()> {
        xmss_fast_update(
            self.hash_function,
            &self.xmss_params,
            &mut self.sk,
            &mut self.bds_state,
            new_index,
        )
    }

    /// Produce an XMSS signature over `message` using the next unused
    /// one-time-signature index, then advance the internal index.
    ///
    /// # CRITICAL — index persistence (TOB-QRLLIB-8)
    ///
    /// XMSS is a stateful one-time-signature scheme. The internal OTS
    /// index returned by [`Xmss::index`] **MUST** be persisted to
    /// durable storage *after* this call returns and *before* the
    /// returned signature is used or broadcast. If the process crashes
    /// or the persist step fails between this `sign` returning and the
    /// signature being committed, restarting from the previously-saved
    /// index will reuse the OTS key for a different message — and a
    /// single OTS key reuse lets any observer forge signatures on
    /// (most) messages under the same public key, an irreversible
    /// compromise of the entire tree.
    ///
    /// The safe pattern is:
    ///
    /// ```ignore
    /// let sig = tree.sign(&message)?;
    /// persist_index(tree.index())?;  // MUST succeed before...
    /// broadcast(sig);                 // ...the signature leaves the host.
    /// ```
    ///
    /// If `persist_index` fails, the signature **must not** be used —
    /// drop it and treat the in-memory tree as compromised relative to
    /// the persisted state until the index can be reconciled.
    ///
    /// See the `Xmss` type doc and `SECURITY.md` "XMSS State Management"
    /// for the full set of requirements (no concurrent signing, no
    /// state rollback, key rotation before tree exhaustion).
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let index = self.index();
        self.set_index(index)?;
        xmss_fast_sign_message(
            self.hash_function,
            &self.xmss_params,
            &mut self.sk,
            &mut self.bds_state,
            message,
        )
    }

    pub fn zeroize(&mut self) {
        // Use slice-level `zeroize` on the owned `Vec`s so that the byte
        // contents are cleared but the buffer length is preserved. Calling
        // `Vec::zeroize` directly truncates the vector to length 0, which
        // would turn subsequent read attempts on the zeroized signer into
        // out-of-bounds panics; after this routine a caller can still call
        // `sign` and receive a clean `QrllibError::XmssSecretKeyZeroized`.
        self.sk.as_mut_slice().zeroize();
        self.seed.as_mut_slice().zeroize();
        self.bds_state.zeroize();
    }
}

impl Drop for Xmss {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn get_xmss_height_from_sig_size(sig_size: u32, wots_param_w: u32) -> Result<XmssHeight> {
    let wots_params = WotsParams::new(XMSS_WOTS_PARAM_N, wots_param_w)?;
    let signature_base_size = calculate_signature_base_size(wots_params.key_size);
    if sig_size < signature_base_size {
        return Err(QrllibError::InvalidSignatureSize(
            sig_size as usize,
            signature_base_size as usize,
        ));
    }
    if !(sig_size - 4).is_multiple_of(32) {
        return Err(QrllibError::InvalidSignatureSize(
            sig_size as usize,
            signature_base_size as usize,
        ));
    }
    XmssHeight::from_u32((sig_size - signature_base_size) / 32)
}

pub fn verify_xmss(
    hash_function: XmssHashFunction,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    verify_xmss_with_custom_wots_param_w(
        hash_function,
        message,
        signature,
        public_key,
        XMSS_WOTS_PARAM_W,
    )
}

pub fn verify_xmss_with_custom_wots_param_w(
    hash_function: XmssHashFunction,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    wots_param_w: u32,
) -> bool {
    if !matches!(wots_param_w, 4 | 16 | 256) {
        return false;
    }

    // Coverage: `WotsParams::new` only fails when `wots_param_w` is outside
    // {4, 16, 256}, but the preceding `matches!` guard already rejects those.
    // Kept as defence-in-depth if the two guards ever drift apart.
    let Ok(wots_params) = WotsParams::new(XMSS_WOTS_PARAM_N, wots_param_w) else {
        return false;
    };
    let signature_base_size = calculate_signature_base_size(wots_params.key_size);
    let sig_size = signature.len() as u32;
    if sig_size < signature_base_size {
        return false;
    }
    if !(sig_size - 4).is_multiple_of(32) {
        return false;
    }
    if sig_size > signature_base_size + u32::from(XMSS_MAX_HEIGHT) * 32 {
        return false;
    }

    // Coverage: `get_xmss_height_from_sig_size` returns Err only when the size
    // bounds above are violated — already rejected. Kept for symmetry with the
    // reference implementation; adding callers from other entry points could
    // reach it.
    let Ok(height) = get_xmss_height_from_sig_size(sig_size, wots_param_w) else {
        return false;
    };
    let height_u32 = height.as_u32();
    if XMSS_WOTS_PARAM_K >= height_u32 || (height_u32 - XMSS_WOTS_PARAM_K) % 2 == 1 {
        return false;
    }

    // Coverage: `XmssParams::new` only fails for `wots_param_w` outside
    // {4, 16, 256} — already rejected. Kept as defence-in-depth.
    let Ok(params) =
        XmssParams::new(XMSS_WOTS_PARAM_N, height_u32, wots_param_w, XMSS_WOTS_PARAM_K)
    else {
        return false;
    };

    verify_sig(hash_function, &params.wots_params, message, signature, public_key, height_u32)
}

impl WotsParams {
    fn new(n: u32, w: u32) -> Result<Self> {
        let log_w = match w {
            4 => 2,
            16 => 4,
            256 => 8,
            _ => return Err(QrllibError::InvalidXmssWotsParameter(w)),
        };

        let len1 = (8 * n).div_ceil(log_w);
        let mut len2 = 0_u32;
        let mut value = len1 * (w - 1);
        while value > 0 {
            len2 += 1;
            value >>= log_w;
        }
        let len = len1 + len2;
        let key_size = len * n;

        Ok(Self { len1, len2, len, n, w, log_w, key_size })
    }
}

impl XmssParams {
    fn new(n: u32, h: u32, w: u32, k: u32) -> Result<Self> {
        Ok(Self { wots_params: WotsParams::new(n, w)?, n, h, k })
    }
}

impl BdsState {
    fn new(height: u32, n: u32, k: u32) -> Self {
        let mut tree_hash = Vec::new();
        for _ in 0..(height - k) {
            tree_hash.push(TreeHashInst {
                h: 0,
                next_idx: 0,
                stack_usage: 0,
                completed: false,
                node: vec![0_u8; n as usize],
            });
        }

        Self {
            stack: vec![0_u8; ((height + 1) * n) as usize],
            stack_offset: 0,
            stack_levels: vec![0_u32; (height + 1) as usize],
            auth: vec![0_u8; (height * n) as usize],
            keep: vec![0_u8; ((height >> 1) * n) as usize],
            tree_hash,
            retain: vec![0_u8; (((1 << k) - k - 1) * n) as usize],
        }
    }

    fn zeroize(&mut self) {
        // See the note on `Xmss::zeroize` — clear byte contents but preserve
        // the `Vec` buffer lengths so later reads do not panic.
        self.stack.as_mut_slice().zeroize();
        self.auth.as_mut_slice().zeroize();
        self.keep.as_mut_slice().zeroize();
        self.retain.as_mut_slice().zeroize();
        for tree_hash in &mut self.tree_hash {
            tree_hash.node.as_mut_slice().zeroize();
        }
    }
}

fn shake128(output: &mut [u8], message: &[u8]) {
    let mut hasher = shake::Shake128::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

fn shake256(output: &mut [u8], message: &[u8]) {
    let mut hasher = shake::Shake256::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

fn sha256(output: &mut [u8], message: &[u8]) {
    let digest = Sha256::digest(message);
    output.copy_from_slice(&digest[..output.len()]);
}

fn set_type(address: &mut [u32; 8], type_value: u32) {
    address[3] = type_value;
    for item in &mut address[4..] {
        *item = 0;
    }
}

fn set_ots_address(address: &mut [u32; 8], ots: u32) {
    address[4] = ots;
}

fn set_chain_address(address: &mut [u32; 8], chain: u32) {
    address[5] = chain;
}

fn set_hash_address(address: &mut [u32; 8], hash: u32) {
    address[6] = hash;
}

fn set_ltree_address(address: &mut [u32; 8], ltree: u32) {
    address[4] = ltree;
}

fn set_tree_height(address: &mut [u32; 8], tree_height: u32) {
    address[5] = tree_height;
}

fn set_tree_index(address: &mut [u32; 8], tree_index: u32) {
    address[6] = tree_index;
}

fn set_key_and_mask(address: &mut [u32; 8], key_and_mask: u32) {
    address[7] = key_and_mask;
}

fn to_byte_big_endian(output: &mut [u8], mut input: u32, bytes: usize) {
    for index in (0..bytes).rev() {
        output[index] = (input & 0xff) as u8;
        input >>= 8;
    }
}

fn address_to_bytes(output: &mut [u8; 32], address: &[u32; 8]) {
    for (index, value) in address.iter().enumerate() {
        to_byte_big_endian(&mut output[index * 4..index * 4 + 4], *value, 4);
    }
}

fn read_index(secret_key: &[u8]) -> u32 {
    (u32::from(secret_key[0]) << 24)
        | (u32::from(secret_key[1]) << 16)
        | (u32::from(secret_key[2]) << 8)
        | u32::from(secret_key[3])
}

fn write_index(secret_key: &mut [u8], index: u32) {
    secret_key[0] = ((index >> 24) & 0xff) as u8;
    secret_key[1] = ((index >> 16) & 0xff) as u8;
    secret_key[2] = ((index >> 8) & 0xff) as u8;
    secret_key[3] = (index & 0xff) as u8;
}

fn hash_h(
    hash_function: XmssHashFunction,
    output: &mut [u8],
    input: &[u8],
    public_seed: &[u8],
    address: &mut [u32; 8],
    n: u32,
) {
    let n = n as usize;
    let mut buf = vec![0_u8; 2 * n];
    let mut key = vec![0_u8; n];
    let mut bit_mask = vec![0_u8; 2 * n];
    let mut byte_addr = [0_u8; 32];

    set_key_and_mask(address, 0);
    address_to_bytes(&mut byte_addr, address);
    prf(hash_function, &mut key, &byte_addr, public_seed, n as u32);

    set_key_and_mask(address, 1);
    address_to_bytes(&mut byte_addr, address);
    prf(hash_function, &mut bit_mask[..n], &byte_addr, public_seed, n as u32);

    set_key_and_mask(address, 2);
    address_to_bytes(&mut byte_addr, address);
    prf(hash_function, &mut bit_mask[n..], &byte_addr, public_seed, n as u32);

    for index in 0..(2 * n) {
        buf[index] = input[index] ^ bit_mask[index];
    }
    core_hash(hash_function, output, 1, &key, &buf, n as u32);
}

/// PRF computes the RFC 8391 pseudo-random function over a fixed
/// 32-byte input. The `input` parameter is typed `&[u8; 32]` rather
/// than `&[u8]` to pin the input length at compile time: every call
/// site already passes a 32-byte stack-allocated array, and the
/// underlying `core_hash` dispatch reads exactly 32 bytes regardless
/// of slice length, so a shorter slice would silently truncate the
/// PRF domain separator. (TOB-QRLLIB-5 — Rust-port parity with the
/// Go-side `*[32]uint8` pin.)
fn prf(
    hash_function: XmssHashFunction,
    output: &mut [u8],
    input: &[u8; 32],
    key: &[u8],
    key_len: u32,
) {
    let _ = key_len;
    core_hash(hash_function, output, 3, key, input, output.len() as u32);
}

fn core_hash(
    hash_function: XmssHashFunction,
    output: &mut [u8],
    type_value: u32,
    key: &[u8],
    input: &[u8],
    n: u32,
) {
    let n = n as usize;
    let mut buf = vec![0_u8; input.len() + n + key.len()];
    to_byte_big_endian(&mut buf[..n], type_value, n);
    buf[n..n + key.len()].copy_from_slice(key);
    buf[n + key.len()..].copy_from_slice(input);

    match hash_function {
        XmssHashFunction::Sha2_256 => sha256(output, &buf),
        XmssHashFunction::Shake128 => shake128(output, &buf),
        XmssHashFunction::Shake256 => shake256(output, &buf),
    }
}

fn hash_f(
    hash_function: XmssHashFunction,
    output: &mut [u8],
    input: &[u8],
    public_seed: &[u8],
    address: &mut [u32; 8],
    n: u32,
) {
    let n = n as usize;
    let mut buf = vec![0_u8; n];
    let mut key = vec![0_u8; n];
    let mut bit_mask = vec![0_u8; n];
    let mut byte_addr = [0_u8; 32];

    set_key_and_mask(address, 0);
    address_to_bytes(&mut byte_addr, address);
    prf(hash_function, &mut key, &byte_addr, public_seed, n as u32);

    set_key_and_mask(address, 1);
    address_to_bytes(&mut byte_addr, address);
    prf(hash_function, &mut bit_mask, &byte_addr, public_seed, n as u32);

    for index in 0..n {
        buf[index] = input[index] ^ bit_mask[index];
    }
    core_hash(hash_function, output, 0, &key, &buf, n as u32);
}

fn h_msg(
    hash_function: XmssHashFunction,
    output: &mut [u8],
    input: &[u8],
    key: &[u8],
    n: u32,
) -> Result<()> {
    if key.len() != (3 * n) as usize {
        return Err(QrllibError::InvalidXmssKeyLength(key.len()));
    }
    core_hash(hash_function, output, 2, key, input, n);
    Ok(())
}

fn calculate_signature_base_size(key_size: u32) -> u32 {
    4 + 32 + key_size
}

fn get_signature_size(params: &XmssParams) -> u32 {
    calculate_signature_base_size(params.wots_params.key_size) + params.h * 32
}

fn get_seed(
    hash_function: XmssHashFunction,
    seed: &mut [u8],
    sk_seed: &[u8],
    n: u32,
    address: &mut [u32; 8],
) {
    let mut bytes = [0_u8; 32];
    set_chain_address(address, 0);
    set_hash_address(address, 0);
    set_key_and_mask(address, 0);
    address_to_bytes(&mut bytes, address);
    prf(hash_function, seed, &bytes, sk_seed, n);
}

fn expand_seed(
    hash_function: XmssHashFunction,
    out_seeds: &mut [u8],
    in_seeds: &[u8],
    n: u32,
    len: u32,
) {
    let mut counter = [0_u8; 32];
    for index in 0..len {
        to_byte_big_endian(&mut counter, index, 32);
        let start = (index * n) as usize;
        prf(hash_function, &mut out_seeds[start..start + n as usize], &counter, in_seeds, n);
    }
}

#[allow(clippy::too_many_arguments)]
fn gen_chain(
    hash_function: XmssHashFunction,
    output: &mut [u8],
    input: &[u8],
    start: u32,
    steps: u32,
    params: &WotsParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    output.copy_from_slice(input);
    for step in start..(start + steps).min(params.w) {
        set_hash_address(address, step);
        let current = output.to_vec();
        hash_f(hash_function, output, &current, public_seed, address, params.n);
    }
}

fn wots_pk_gen(
    hash_function: XmssHashFunction,
    public_key: &mut [u8],
    secret_key: &[u8],
    wots_params: &WotsParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    expand_seed(hash_function, public_key, secret_key, wots_params.n, wots_params.len);

    for index in 0..wots_params.len {
        set_chain_address(address, index);
        let start = (index * wots_params.n) as usize;
        let current = public_key[start..start + wots_params.n as usize].to_vec();
        gen_chain(
            hash_function,
            &mut public_key[start..start + wots_params.n as usize],
            &current,
            0,
            wots_params.w - 1,
            wots_params,
            public_seed,
            address,
        );
    }
}

fn gen_leaf_wots(
    hash_function: XmssHashFunction,
    leaf: &mut [u8],
    sk_seed: &[u8],
    xmss_params: &XmssParams,
    public_seed: &[u8],
    ltree_address: &mut [u32; 8],
    ots_address: &mut [u32; 8],
) {
    let mut seed = vec![0_u8; xmss_params.n as usize];
    let mut public_key = vec![0_u8; xmss_params.wots_params.key_size as usize];
    get_seed(hash_function, &mut seed, sk_seed, xmss_params.n, ots_address);
    wots_pk_gen(
        hash_function,
        &mut public_key,
        &seed,
        &xmss_params.wots_params,
        public_seed,
        ots_address,
    );
    l_tree(
        hash_function,
        &xmss_params.wots_params,
        leaf,
        &mut public_key,
        public_seed,
        ltree_address,
    );
}

fn l_tree(
    hash_function: XmssHashFunction,
    params: &WotsParams,
    leaf: &mut [u8],
    wots_public_key: &mut [u8],
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    let mut length = params.len;
    let n = params.n as usize;
    let mut height = 0_u32;
    set_tree_height(address, height);

    while length > 1 {
        let bound = length >> 1;
        for index in 0..bound {
            set_tree_index(address, index);
            let out_start = (index as usize) * n;
            let in_start = (index as usize) * 2 * n;
            let input = wots_public_key[in_start..in_start + 2 * n].to_vec();
            let mut output = vec![0_u8; n];
            hash_h(hash_function, &mut output, &input, public_seed, address, params.n);
            wots_public_key[out_start..out_start + n].copy_from_slice(&output);
        }

        if length & 1 == 1 {
            let dest_start = ((length >> 1) as usize) * n;
            let src_start = ((length - 1) as usize) * n;
            let source = wots_public_key[src_start..src_start + n].to_vec();
            wots_public_key[dest_start..dest_start + n].copy_from_slice(&source);
            length = (length >> 1) + 1;
        } else {
            length >>= 1;
        }

        height += 1;
        set_tree_height(address, height);
    }

    leaf.copy_from_slice(&wots_public_key[..n]);
}

#[allow(clippy::too_many_arguments)]
fn tree_hash_setup(
    hash_function: XmssHashFunction,
    node: &mut [u8],
    mut index: u32,
    bds_state: &mut BdsState,
    sk_seed: &[u8],
    xmss_params: &XmssParams,
    public_seed: &[u8],
    address: &[u32],
) {
    let n = xmss_params.n as usize;
    let h = xmss_params.h;
    let k = xmss_params.k;

    let mut ots_address = [0_u32; 8];
    let mut ltree_address = [0_u32; 8];
    let mut node_address = [0_u32; 8];
    ots_address[..3].copy_from_slice(&address[..3]);
    ltree_address[..3].copy_from_slice(&address[..3]);
    node_address[..3].copy_from_slice(&address[..3]);
    set_type(&mut ots_address, 0);
    set_type(&mut ltree_address, 1);
    set_type(&mut node_address, 2);

    let last_node = index + (1 << h);
    let bound = h - k;
    let mut stack = vec![0_u8; ((h + 1) as usize) * n];
    let mut stack_levels = vec![0_u32; (h + 1) as usize];
    let mut stack_offset = 0_usize;
    for (iter, tree_hash) in bds_state.tree_hash.iter_mut().take(bound as usize).enumerate() {
        tree_hash.h = iter as u32;
        tree_hash.completed = true;
        tree_hash.stack_usage = 0;
    }

    let mut i = 0_u32;
    while index < last_node {
        set_ltree_address(&mut ltree_address, index);
        set_ots_address(&mut ots_address, index);

        gen_leaf_wots(
            hash_function,
            &mut stack[stack_offset * n..stack_offset * n + n],
            sk_seed,
            xmss_params,
            public_seed,
            &mut ltree_address,
            &mut ots_address,
        );
        stack_levels[stack_offset] = 0;
        stack_offset += 1;

        // Faithful-port checkpoint (mirrors xmss-reference xmss_fast.c at
        // i==3): this seeds tree_hash[0] from the freshly pushed leaf, a
        // value that the `(i >> node_height) == 3` branch in the merge loop
        // below overwrites within the same iteration, so it never reaches
        // the output for the supported QRL parameters. Kept to preserve
        // reference equivalence; do not alter without re-running the
        // bidirectional cross-verify.
        if h > k && i == 3 {
            let src = stack[(stack_offset - 1) * n..stack_offset * n].to_vec();
            bds_state.tree_hash[0].node.copy_from_slice(&src);
        }

        while stack_offset > 1 && stack_levels[stack_offset - 1] == stack_levels[stack_offset - 2] {
            let node_height = stack_levels[stack_offset - 1];
            if (i >> node_height) == 1 {
                let auth_start = (node_height as usize) * n;
                let stack_start = (stack_offset - 1) * n;
                let src = stack[stack_start..stack_start + n].to_vec();
                bds_state.auth[auth_start..auth_start + n].copy_from_slice(&src);
            } else if node_height < h - k && (i >> node_height) == 3 {
                let stack_start = (stack_offset - 1) * n;
                let src = stack[stack_start..stack_start + n].to_vec();
                bds_state.tree_hash[node_height as usize].node.copy_from_slice(&src);
            } else if node_height >= h - k {
                let retain_start = (((1 << (h - 1 - node_height)) + node_height - h
                    + (((i >> node_height) - 3) >> 1))
                    as usize)
                    * n;
                let stack_start = (stack_offset - 1) * n;
                let src = stack[stack_start..stack_start + n].to_vec();
                bds_state.retain[retain_start..retain_start + n].copy_from_slice(&src);
            }

            set_tree_height(&mut node_address, stack_levels[stack_offset - 1]);
            set_tree_index(&mut node_address, index >> (stack_levels[stack_offset - 1] + 1));
            let stack_start = (stack_offset - 2) * n;
            let input = stack[stack_start..stack_start + 2 * n].to_vec();
            let mut output = vec![0_u8; n];
            hash_h(
                hash_function,
                &mut output,
                &input,
                public_seed,
                &mut node_address,
                xmss_params.n,
            );
            stack[stack_start..stack_start + n].copy_from_slice(&output);
            stack_levels[stack_offset - 2] += 1;
            stack_offset -= 1;
        }

        i += 1;
        index += 1;
    }

    node.copy_from_slice(&stack[..n]);
}

fn xmss_fast_gen_key_pair(
    hash_function: XmssHashFunction,
    xmss_params: &XmssParams,
    public_key: &mut [u8],
    secret_key: &mut [u8],
    bds_state: &mut BdsState,
    seed: &[u8],
) -> Result<()> {
    // Reject seeds that are not exactly XMSS_SEED_SIZE (48) bytes. SHAKE256
    // happily expands any input length, so without this guard an empty or
    // truncated seed silently produces an entropy-starved tree. Mirrors the
    // `initialize_tree` boundary check (go-qrllib `XMSSFastGenKeyPair`).
    if seed.len() != XMSS_SEED_SIZE {
        return Err(QrllibError::InvalidSeedSize(seed.len(), XMSS_SEED_SIZE));
    }

    // QRL convention: SHAKE-256-expand the caller-supplied seed into 96
    // bytes of (SK_SEED || SK_PRF || PUB_SEED), then delegate to the
    // shared keypair-derivation core. The RFC 8391 reference takes the
    // 96 bytes directly — see [`xmss_fast_gen_key_pair_from_expanded_seed`]
    // and the `rfc8391` interop module.
    let mut expanded_seed = [0_u8; 96];
    shake256(&mut expanded_seed, seed);
    xmss_fast_gen_key_pair_from_expanded_seed(
        hash_function,
        xmss_params,
        public_key,
        secret_key,
        bds_state,
        &expanded_seed,
    )
}

/// Shared keypair-derivation core for the QRL XMSS construction. Takes
/// 96 bytes of pre-expanded seed material (`SK_SEED || SK_PRF ||
/// PUB_SEED`) directly — same layout as RFC 8391's reference
/// implementation — and writes the secret key + Merkle root +
/// public_seed into the caller-supplied buffers.
///
/// Both the QRL primary entry point ([`xmss_fast_gen_key_pair`], which
/// SHAKE-256-expands a 48-byte QRL seed first) and the RFC 8391 interop
/// path ([`crate::xmss::rfc8391::new_keypair`], which takes the 96
/// bytes directly) call into this function after their respective seed
/// preprocessing. (TOB-QRLLIB-1 part 2 — Rust-port parity with the
/// Go-side `XMSSFastGenKeyPairFromExpandedSeed`.)
fn xmss_fast_gen_key_pair_from_expanded_seed(
    hash_function: XmssHashFunction,
    xmss_params: &XmssParams,
    public_key: &mut [u8],
    secret_key: &mut [u8],
    bds_state: &mut BdsState,
    expanded_seed: &[u8; 96],
) -> Result<()> {
    if xmss_params.h & 1 == 1 {
        return Err(QrllibError::InvalidXmssHeight(xmss_params.h as u8));
    }

    let n = xmss_params.n as usize;
    write_index(secret_key, 0);

    secret_key[4..100].copy_from_slice(&expanded_seed[..96]);
    public_key[n..n + 32].copy_from_slice(&secret_key[4 + 2 * n..4 + 2 * n + 32]);

    let address = vec![0_u32; 8];
    tree_hash_setup(
        hash_function,
        &mut public_key[..32],
        0,
        bds_state,
        &secret_key[4..4 + n],
        xmss_params,
        &secret_key[4 + 2 * n..4 + 3 * n],
        &address,
    );
    secret_key[4 + 3 * n..4 + 4 * n].copy_from_slice(&public_key[..32]);
    Ok(())
}

fn xmss_fast_sign_message(
    hash_function: XmssHashFunction,
    params: &XmssParams,
    secret_key: &mut [u8],
    bds_state: &mut BdsState,
    message: &[u8],
) -> Result<Vec<u8>> {
    let n = params.n as usize;

    // Reject signing when the secret-key buffer has been zeroized. Leading
    // zeros are expected on a fresh tree (index = 0); the check is on the
    // sk_seed / sk_prf / pub_seed / root region at offsets [4, 4 + 4n).
    let key_region_end = 4 + 4 * n;
    let mut any_nonzero = 0_u8;
    for byte in secret_key[4..key_region_end].iter() {
        any_nonzero |= byte;
    }
    if any_nonzero == 0 {
        return Err(QrllibError::XmssSecretKeyZeroized);
    }

    let idx = read_index(secret_key);

    let sk_seed = secret_key[4..4 + n].to_vec();
    let sk_prf = secret_key[4 + n..4 + 2 * n].to_vec();
    let public_seed = secret_key[4 + 2 * n..4 + 3 * n].to_vec();

    let mut idx_bytes_32 = [0_u8; 32];
    to_byte_big_endian(&mut idx_bytes_32, idx, 32);

    let mut hash_key = vec![0_u8; 3 * n];
    write_index(secret_key, idx + 1);

    let mut r = vec![0_u8; n];
    let mut ots_address = [0_u32; 8];
    prf(hash_function, &mut r, &idx_bytes_32, &sk_prf, n as u32);
    hash_key[..n].copy_from_slice(&r);
    hash_key[n..2 * n].copy_from_slice(&secret_key[4 + 3 * n..4 + 4 * n]);
    to_byte_big_endian(&mut hash_key[2 * n..3 * n], idx, n);

    let mut message_hash = vec![0_u8; n];
    h_msg(hash_function, &mut message_hash, message, &hash_key, params.n)?;

    let mut signature = vec![0_u8; get_signature_size(params) as usize];
    signature[0] = ((idx >> 24) & 0xff) as u8;
    signature[1] = ((idx >> 16) & 0xff) as u8;
    signature[2] = ((idx >> 8) & 0xff) as u8;
    signature[3] = (idx & 0xff) as u8;
    signature[4..4 + n].copy_from_slice(&r);

    set_type(&mut ots_address, 0);
    set_ots_address(&mut ots_address, idx);

    let mut ots_seed = vec![0_u8; n];
    get_seed(hash_function, &mut ots_seed, &sk_seed, params.n, &mut ots_address);

    let mut signature_offset = 4 + n;
    wots_sign(
        hash_function,
        &mut signature[signature_offset..signature_offset + params.wots_params.key_size as usize],
        &message_hash,
        &ots_seed,
        &params.wots_params,
        &public_seed,
        &mut ots_address,
    );
    signature_offset += params.wots_params.key_size as usize;
    signature[signature_offset..signature_offset + params.h as usize * n]
        .copy_from_slice(&bds_state.auth[..params.h as usize * n]);

    if idx < (1 << params.h) - 1 {
        bds_round(hash_function, bds_state, idx, &sk_seed, params, &public_seed, &mut ots_address);
        let _ = bds_tree_hash_update(
            hash_function,
            bds_state,
            (params.h - params.k) >> 1,
            &sk_seed,
            params,
            &public_seed,
            &mut ots_address,
        );
    }

    Ok(signature)
}

fn xmss_fast_update(
    hash_function: XmssHashFunction,
    params: &XmssParams,
    secret_key: &mut [u8],
    bds_state: &mut BdsState,
    new_idx: u32,
) -> Result<()> {
    let num_elements = 1_u32 << params.h;
    let current_idx = read_index(secret_key);

    if new_idx >= num_elements {
        return Err(QrllibError::XmssOtsIndexTooHigh);
    }
    if new_idx < current_idx {
        return Err(QrllibError::XmssOtsIndexRewind);
    }

    let sk_seed = secret_key[4..4 + params.n as usize].to_vec();
    let public_seed = secret_key[OFFSET_PUB_SEED..OFFSET_PUB_SEED + params.n as usize].to_vec();
    let mut ots_address = [0_u32; 8];

    for index in current_idx..new_idx {
        // Coverage: unreachable because `new_idx` is clamped by the earlier
        // `XmssOtsIndexTooHigh` check against `num_elements`. Kept as an
        // internal-invariant assertion — if BDS bookkeeping ever drifts, we
        // surface it as an error rather than indexing out of bounds.
        if index >= num_elements {
            return Err(QrllibError::XmssInternal);
        }
        bds_round(
            hash_function,
            bds_state,
            index,
            &sk_seed,
            params,
            &public_seed,
            &mut ots_address,
        );
        let _ = bds_tree_hash_update(
            hash_function,
            bds_state,
            (params.h - params.k) >> 1,
            &sk_seed,
            params,
            &public_seed,
            &mut ots_address,
        );
    }

    write_index(secret_key, new_idx);
    Ok(())
}

fn bds_round(
    hash_function: XmssHashFunction,
    bds_state: &mut BdsState,
    leaf_idx: u32,
    sk_seed: &[u8],
    params: &XmssParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    let n = params.n as usize;
    let h = params.h;
    let k = params.k;
    let mut tau = h;
    let mut buf = vec![0_u8; 2 * n];

    let mut ots_address = [0_u32; 8];
    let mut ltree_address = [0_u32; 8];
    let mut node_address = [0_u32; 8];
    ots_address[..3].copy_from_slice(&address[..3]);
    ltree_address[..3].copy_from_slice(&address[..3]);
    node_address[..3].copy_from_slice(&address[..3]);
    set_type(&mut ots_address, 0);
    set_type(&mut ltree_address, 1);
    set_type(&mut node_address, 2);

    for index in 0..h {
        if ((leaf_idx >> index) & 1) == 0 {
            tau = index;
            break;
        }
    }

    if tau > 0 {
        let src = ((tau - 1) as usize) * n;
        buf[..n].copy_from_slice(&bds_state.auth[src..src + n]);
        let src = (((tau - 1) >> 1) as usize) * n;
        buf[n..2 * n].copy_from_slice(&bds_state.keep[src..src + n]);
    }

    if ((leaf_idx >> (tau + 1)) & 1) == 0 && tau < h - 1 {
        let dest = ((tau >> 1) as usize) * n;
        let src = (tau as usize) * n;
        let auth = bds_state.auth[src..src + n].to_vec();
        bds_state.keep[dest..dest + n].copy_from_slice(&auth);
    }

    if tau == 0 {
        set_ltree_address(&mut ltree_address, leaf_idx);
        set_ots_address(&mut ots_address, leaf_idx);
        gen_leaf_wots(
            hash_function,
            &mut bds_state.auth[..n],
            sk_seed,
            params,
            public_seed,
            &mut ltree_address,
            &mut ots_address,
        );
    } else {
        set_tree_height(&mut node_address, tau - 1);
        set_tree_index(&mut node_address, leaf_idx >> tau);
        let mut output = vec![0_u8; n];
        hash_h(hash_function, &mut output, &buf, public_seed, &mut node_address, params.n);
        let start = (tau as usize) * n;
        bds_state.auth[start..start + n].copy_from_slice(&output);

        for index in 0..tau {
            if index < h - k {
                let src = bds_state.tree_hash[index as usize].node.clone();
                let dest = (index as usize) * n;
                bds_state.auth[dest..dest + n].copy_from_slice(&src);
            } else {
                let offset = (1 << (h - 1 - index)) + index - h;
                let row_idx = ((leaf_idx >> index) - 1) >> 1;
                let src = ((offset + row_idx) as usize) * n;
                let dest = (index as usize) * n;
                let value = bds_state.retain[src..src + n].to_vec();
                bds_state.auth[dest..dest + n].copy_from_slice(&value);
            }
        }

        let compare_value = (h - k).min(tau);
        for index in 0..compare_value {
            let start_idx = leaf_idx + 1 + 3 * (1 << index);
            if start_idx < (1 << h) {
                let tree_hash = &mut bds_state.tree_hash[index as usize];
                tree_hash.h = index;
                tree_hash.next_idx = start_idx;
                tree_hash.completed = false;
                tree_hash.stack_usage = 0;
            }
        }
    }
}

fn tree_hash_min_height_on_stack(
    state: &BdsState,
    params: &XmssParams,
    tree_hash: &TreeHashInst,
) -> u32 {
    let mut result = params.h;
    for index in 0..tree_hash.stack_usage as usize {
        let level = state.stack_levels[state.stack_offset - index - 1];
        if level < result {
            result = level;
        }
    }
    result
}

fn tree_hash_update(
    hash_function: XmssHashFunction,
    tree_hash_index: usize,
    bds_state: &mut BdsState,
    sk_seed: &[u8],
    params: &XmssParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    let n = params.n as usize;

    let mut ots_address = [0_u32; 8];
    let mut ltree_address = [0_u32; 8];
    let mut node_address = [0_u32; 8];
    ots_address[..3].copy_from_slice(&address[..3]);
    ltree_address[..3].copy_from_slice(&address[..3]);
    node_address[..3].copy_from_slice(&address[..3]);
    set_type(&mut ots_address, 0);
    set_type(&mut ltree_address, 1);
    set_type(&mut node_address, 2);

    let next_idx = bds_state.tree_hash[tree_hash_index].next_idx;
    set_ltree_address(&mut ltree_address, next_idx);
    set_ots_address(&mut ots_address, next_idx);

    let mut node_buffer = vec![0_u8; 2 * n];
    let mut node_height = 0_u32;
    gen_leaf_wots(
        hash_function,
        &mut node_buffer[..n],
        sk_seed,
        params,
        public_seed,
        &mut ltree_address,
        &mut ots_address,
    );

    while bds_state.tree_hash[tree_hash_index].stack_usage > 0
        && bds_state.stack_levels[bds_state.stack_offset - 1] == node_height
    {
        let previous = node_buffer[..n].to_vec();
        node_buffer[n..2 * n].copy_from_slice(&previous);
        let src_offset = (bds_state.stack_offset - 1) * n;
        let src = bds_state.stack[src_offset..src_offset + n].to_vec();
        node_buffer[..n].copy_from_slice(&src);
        set_tree_height(&mut node_address, node_height);
        set_tree_index(
            &mut node_address,
            bds_state.tree_hash[tree_hash_index].next_idx >> (node_height + 1),
        );
        let mut output = vec![0_u8; n];
        hash_h(hash_function, &mut output, &node_buffer, public_seed, &mut node_address, params.n);
        node_buffer[..n].copy_from_slice(&output);
        node_height += 1;
        bds_state.tree_hash[tree_hash_index].stack_usage -= 1;
        bds_state.stack_offset -= 1;
    }

    if node_height == bds_state.tree_hash[tree_hash_index].h {
        bds_state.tree_hash[tree_hash_index].node.copy_from_slice(&node_buffer[..n]);
        bds_state.tree_hash[tree_hash_index].completed = true;
    } else {
        let dest_offset = bds_state.stack_offset * n;
        bds_state.stack[dest_offset..dest_offset + n].copy_from_slice(&node_buffer[..n]);
        bds_state.tree_hash[tree_hash_index].stack_usage += 1;
        bds_state.stack_levels[bds_state.stack_offset] = node_height;
        bds_state.stack_offset += 1;
        bds_state.tree_hash[tree_hash_index].next_idx += 1;
    }
}

fn bds_tree_hash_update(
    hash_function: XmssHashFunction,
    bds_state: &mut BdsState,
    updates: u32,
    sk_seed: &[u8],
    params: &XmssParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) -> u32 {
    let h = params.h;
    let k = params.k;
    let mut used = 0_u32;

    for _ in 0..updates {
        let mut min_level = h;
        let mut level = h - k;

        for index in 0..(h - k) as usize {
            let low = if bds_state.tree_hash[index].completed {
                h
            } else if bds_state.tree_hash[index].stack_usage == 0 {
                index as u32
            } else {
                tree_hash_min_height_on_stack(bds_state, params, &bds_state.tree_hash[index])
            };

            if low < min_level {
                level = index as u32;
                min_level = low;
            }
        }

        if level == h - k {
            break;
        }

        tree_hash_update(
            hash_function,
            level as usize,
            bds_state,
            sk_seed,
            params,
            public_seed,
            address,
        );
        used += 1;
    }

    updates - used
}

fn calc_base_w(output: &mut [u8], output_len: u32, input: &[u8], params: &WotsParams) {
    let mut input_index = 0_usize;
    let mut total = 0_u32;
    let mut bits = 0_u32;

    for value in output.iter_mut().take(output_len as usize) {
        if bits == 0 {
            total = u32::from(input[input_index]);
            input_index += 1;
            bits += 8;
        }
        bits -= params.log_w;
        *value = ((total >> bits) & (params.w - 1)) as u8;
    }
}

fn wots_sign(
    hash_function: XmssHashFunction,
    signature: &mut [u8],
    message: &[u8],
    secret_key: &[u8],
    params: &WotsParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    let mut base_w = vec![0_u8; params.len as usize];
    let mut checksum = 0_u32;
    calc_base_w(&mut base_w, params.len1, message, params);
    for value in base_w.iter().take(params.len1 as usize) {
        checksum += params.w - 1 - u32::from(*value);
    }

    checksum <<= 8 - ((params.len2 * params.log_w) % 8);
    let len2_bytes = (params.len2 * params.log_w).div_ceil(8);
    let mut checksum_bytes = vec![0_u8; len2_bytes as usize];
    to_byte_big_endian(&mut checksum_bytes, checksum, len2_bytes as usize);
    let mut checksum_base_w = vec![0_u8; params.len2 as usize];
    calc_base_w(&mut checksum_base_w, params.len2, &checksum_bytes, params);

    for index in 0..params.len2 as usize {
        base_w[params.len1 as usize + index] = checksum_base_w[index];
    }

    expand_seed(hash_function, signature, secret_key, params.n, params.len);
    for index in 0..params.len {
        set_chain_address(address, index);
        let start = (index * params.n) as usize;
        let current = signature[start..start + params.n as usize].to_vec();
        gen_chain(
            hash_function,
            &mut signature[start..start + params.n as usize],
            &current,
            0,
            u32::from(base_w[index as usize]),
            params,
            public_seed,
            address,
        );
    }
}

fn wots_pk_from_sig(
    hash_function: XmssHashFunction,
    public_key: &mut [u8],
    signature: &[u8],
    message: &[u8],
    wots_params: &WotsParams,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    let mut base_w = vec![0_u8; wots_params.len as usize];
    let mut checksum = 0_u32;
    let checksum_len = (wots_params.len2 * wots_params.log_w).div_ceil(8) as usize;
    let mut checksum_bytes = vec![0_u8; checksum_len];
    let mut checksum_base_w = vec![0_u8; wots_params.len2 as usize];

    calc_base_w(&mut base_w, wots_params.len1, message, wots_params);
    for value in base_w.iter().take(wots_params.len1 as usize) {
        checksum += wots_params.w - 1 - u32::from(*value);
    }
    checksum <<= 8 - ((wots_params.len2 * wots_params.log_w) % 8);
    to_byte_big_endian(&mut checksum_bytes, checksum, checksum_len);
    calc_base_w(&mut checksum_base_w, wots_params.len2, &checksum_bytes, wots_params);
    for index in 0..wots_params.len2 as usize {
        base_w[wots_params.len1 as usize + index] = checksum_base_w[index];
    }

    for index in 0..wots_params.len {
        set_chain_address(address, index);
        let start = (index * wots_params.n) as usize;
        gen_chain(
            hash_function,
            &mut public_key[start..start + wots_params.n as usize],
            &signature[start..start + wots_params.n as usize],
            u32::from(base_w[index as usize]),
            wots_params.w - 1 - u32::from(base_w[index as usize]),
            wots_params,
            public_seed,
            address,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_auth_path(
    hash_function: XmssHashFunction,
    root: &mut [u8],
    leaf: &[u8],
    mut leaf_idx: u32,
    auth_path: &[u8],
    n: u32,
    h: u32,
    public_seed: &[u8],
    address: &mut [u32; 8],
) {
    let n = n as usize;
    let mut buffer = vec![0_u8; 2 * n];

    if leaf_idx & 1 == 1 {
        buffer[..n].copy_from_slice(&auth_path[..n]);
        buffer[n..2 * n].copy_from_slice(leaf);
    } else {
        buffer[..n].copy_from_slice(leaf);
        buffer[n..2 * n].copy_from_slice(&auth_path[..n]);
    }

    let mut auth_path_offset = n;
    for index in 0..(h - 1) {
        set_tree_height(address, index);
        leaf_idx >>= 1;
        set_tree_index(address, leaf_idx);
        if leaf_idx & 1 == 1 {
            let mut output = vec![0_u8; n];
            hash_h(hash_function, &mut output, &buffer, public_seed, address, n as u32);
            buffer[n..2 * n].copy_from_slice(&output);
            buffer[..n].copy_from_slice(&auth_path[auth_path_offset..auth_path_offset + n]);
        } else {
            let mut output = vec![0_u8; n];
            hash_h(hash_function, &mut output, &buffer, public_seed, address, n as u32);
            buffer[..n].copy_from_slice(&output);
            buffer[n..2 * n].copy_from_slice(&auth_path[auth_path_offset..auth_path_offset + n]);
        }
        auth_path_offset += n;
    }

    set_tree_height(address, h - 1);
    leaf_idx >>= 1;
    set_tree_index(address, leaf_idx);
    hash_h(hash_function, root, &buffer, public_seed, address, n as u32);
}

fn verify_sig(
    hash_function: XmssHashFunction,
    wots_params: &WotsParams,
    message: &[u8],
    signature_message: &[u8],
    public_key: &[u8],
    h: u32,
) -> bool {
    let n = wots_params.n as usize;
    let expected_len =
        calculate_signature_base_size(wots_params.key_size) as usize + h as usize * n;
    if public_key.len() < 2 * n || signature_message.len() < expected_len {
        return false;
    }

    let mut wots_public_key = vec![0_u8; wots_params.key_size as usize];
    let mut pk_hash = vec![0_u8; n];
    let mut root = vec![0_u8; n];
    let mut hash_key = vec![0_u8; 3 * n];
    let public_seed = public_key[n..2 * n].to_vec();

    let mut ots_address = [0_u32; 8];
    let mut ltree_address = [0_u32; 8];
    let mut node_address = [0_u32; 8];
    set_type(&mut ots_address, 0);
    set_type(&mut ltree_address, 1);
    set_type(&mut node_address, 2);

    let idx = (u32::from(signature_message[0]) << 24)
        | (u32::from(signature_message[1]) << 16)
        | (u32::from(signature_message[2]) << 8)
        | u32::from(signature_message[3]);

    hash_key[..n].copy_from_slice(&signature_message[4..4 + n]);
    hash_key[n..2 * n].copy_from_slice(&public_key[..n]);
    to_byte_big_endian(&mut hash_key[2 * n..3 * n], idx, n);

    let mut message_hash = vec![0_u8; n];
    // Coverage: `h_msg` only errors on unsupported hash-function tags, but the
    // caller selected one from `XmssHashFunction` — all three variants are
    // supported. Kept as defence-in-depth.
    if h_msg(hash_function, &mut message_hash, message, &hash_key, n as u32).is_err() {
        return false;
    }

    let mut signature_offset = n + 4;
    set_ots_address(&mut ots_address, idx);
    wots_pk_from_sig(
        hash_function,
        &mut wots_public_key,
        &signature_message[signature_offset..signature_offset + wots_params.key_size as usize],
        &message_hash,
        wots_params,
        &public_seed,
        &mut ots_address,
    );
    signature_offset += wots_params.key_size as usize;

    set_ltree_address(&mut ltree_address, idx);
    l_tree(
        hash_function,
        wots_params,
        &mut pk_hash,
        &mut wots_public_key,
        &public_seed,
        &mut ltree_address,
    );
    validate_auth_path(
        hash_function,
        &mut root,
        &pk_hash,
        idx,
        &signature_message[signature_offset..signature_offset + h as usize * n],
        n as u32,
        h,
        &public_seed,
        &mut node_address,
    );

    root == public_key[..n]
}

#[cfg(test)]
mod tests {
    use super::{
        BdsState, XMSS_MAX_HEIGHT, XMSS_PUBLIC_KEY_SIZE, XMSS_SECRET_KEY_SIZE, XMSS_WOTS_PARAM_K,
        XMSS_WOTS_PARAM_N, XMSS_WOTS_PARAM_W, Xmss, XmssHashFunction, XmssHeight, XmssParams,
        get_xmss_height_from_sig_size, h_msg, verify_xmss, verify_xmss_with_custom_wots_param_w,
        xmss_fast_gen_key_pair,
    };
    use crate::QrllibError;

    #[test]
    fn xmss_height_validation_matches_go_rules() {
        assert!(XmssHeight::new(4).is_ok());
        assert!(XmssHeight::new(6).is_ok());
        assert!(XmssHeight::new(0).is_err());
        assert!(XmssHeight::new(3).is_err());
        assert!(XmssHeight::new(32).is_err());
        assert_eq!(XmssHeight::from_descriptor_byte(0x03).expect("height").as_u8(), 6);
    }

    #[test]
    fn xmss_initialize_tree_rejects_non_48_byte_seeds() {
        let height = XmssHeight::new(4).expect("height");
        // Exactly 48 bytes is accepted.
        assert!(Xmss::initialize_tree(height, XmssHashFunction::Shake128, &[0_u8; 48]).is_ok());

        // Any other length is rejected with InvalidSeedSize rather than being
        // silently SHAKE256-expanded into an entropy-starved tree (06-2026
        // audit fix; mirrors go-qrllib's InitializeTree boundary check).
        for bad_len in [0_usize, 1, 32, 47, 49, 96] {
            let seed = vec![0_u8; bad_len];
            assert!(
                matches!(
                    Xmss::initialize_tree(height, XmssHashFunction::Shake128, &seed),
                    Err(QrllibError::InvalidSeedSize(actual, 48)) if actual == bad_len
                ),
                "seed length {bad_len} must be rejected with InvalidSeedSize"
            );
        }
    }

    #[test]
    fn xmss_fast_gen_key_pair_rejects_non_48_byte_seeds() {
        let params = XmssParams::new(XMSS_WOTS_PARAM_N, 4, XMSS_WOTS_PARAM_W, XMSS_WOTS_PARAM_K)
            .expect("params");
        let mut bds_state = BdsState::new(4, XMSS_WOTS_PARAM_N, XMSS_WOTS_PARAM_K);
        let mut pk = vec![0_u8; XMSS_PUBLIC_KEY_SIZE];
        let mut sk = vec![0_u8; XMSS_SECRET_KEY_SIZE];
        assert!(matches!(
            xmss_fast_gen_key_pair(
                XmssHashFunction::Shake128,
                &params,
                &mut pk,
                &mut sk,
                &mut bds_state,
                &[0_u8; 47],
            ),
            Err(QrllibError::InvalidSeedSize(47, 48))
        ));
    }

    #[test]
    fn xmss_height_from_signature_size_matches_height() {
        let mut tree = Xmss::initialize_tree(
            XmssHeight::new(4).expect("height"),
            XmssHashFunction::Shake128,
            &[0_u8; 48],
        )
        .expect("tree");
        let signature = tree.sign(b"message").expect("signature");
        assert_eq!(
            get_xmss_height_from_sig_size(signature.len() as u32, super::XMSS_WOTS_PARAM_W)
                .expect("height")
                .as_u8(),
            4
        );
    }

    #[test]
    fn xmss_known_zero_seed_vector_matches_go_outputs() {
        let tree = Xmss::initialize_tree(
            XmssHeight::new(4).expect("height"),
            XmssHashFunction::Shake128,
            &[0_u8; 48],
        )
        .expect("tree");

        assert_eq!(
            hex::encode(tree.root()),
            "c25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d"
        );
        assert_eq!(
            hex::encode(tree.public_seed()),
            "3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d"
        );
    }

    #[test]
    fn xmss_sign_and_verify_round_trip() {
        let mut tree = Xmss::initialize_tree(
            XmssHeight::new(4).expect("height"),
            XmssHashFunction::Shake128,
            &[0_u8; 48],
        )
        .expect("tree");

        let message = b"Hello, XMSS!";
        let signature = tree.sign(message).expect("signature");
        assert_eq!(tree.index(), 1);
        assert!(verify_xmss(XmssHashFunction::Shake128, message, &signature, &tree.public_key(),));
        assert!(!verify_xmss(
            XmssHashFunction::Shake128,
            b"tampered",
            &signature,
            &tree.public_key(),
        ));
    }

    #[test]
    fn xmss_supports_all_hash_functions() {
        for hash_function in
            [XmssHashFunction::Sha2_256, XmssHashFunction::Shake128, XmssHashFunction::Shake256]
        {
            let mut tree = Xmss::initialize_tree(
                XmssHeight::new(4).expect("height"),
                hash_function,
                &[0_u8; 48],
            )
            .expect("tree");
            let signature = tree.sign(b"hash test").expect("signature");
            assert!(verify_xmss(hash_function, b"hash test", &signature, &tree.public_key(),));
        }
    }

    #[test]
    fn xmss_public_api_and_private_validation_paths_are_covered() {
        assert_eq!(XmssHashFunction::try_from(0).expect("sha2"), XmssHashFunction::Sha2_256);
        assert_eq!(XmssHashFunction::try_from(1).expect("shake128"), XmssHashFunction::Shake128);
        assert_eq!(XmssHashFunction::try_from(2).expect("shake256"), XmssHashFunction::Shake256);
        assert!(matches!(
            XmssHashFunction::try_from(9),
            Err(QrllibError::InvalidXmssHashFunction(9))
        ));
        assert_eq!(XmssHashFunction::Sha2_256.to_string(), "SHA2_256");
        assert_eq!(XmssHashFunction::Shake128.to_string(), "SHAKE_128");
        assert_eq!(XmssHashFunction::Shake256.to_string(), "SHAKE_256");

        assert_eq!(XmssHeight::new(4).expect("height").to_string(), "4");
        assert!(matches!(
            XmssHeight::from_u32(u32::from(XMSS_MAX_HEIGHT) + 1),
            Err(QrllibError::InvalidXmssHeight(31))
        ));
        assert!(matches!(XmssHeight(1).descriptor_byte(), Err(QrllibError::InvalidXmssHeight(1))));

        let mut tree = Xmss::initialize_tree(
            XmssHeight::new(4).expect("height"),
            XmssHashFunction::Shake128,
            &[0_u8; 48],
        )
        .expect("tree");
        assert_eq!(tree.seed().as_slice(), &[0_u8; 48]);
        assert_eq!(tree.secret_key().len(), XMSS_SECRET_KEY_SIZE);
        assert_eq!(tree.hash_function(), XmssHashFunction::Shake128);
        assert_eq!(tree.height().as_u8(), 4);

        let signature = tree.sign(b"validation").expect("signature");
        assert!(matches!(
            get_xmss_height_from_sig_size(10, XMSS_WOTS_PARAM_W),
            Err(QrllibError::InvalidSignatureSize(_, _))
        ));
        assert!(matches!(
            get_xmss_height_from_sig_size(signature.len() as u32 - 1, XMSS_WOTS_PARAM_W),
            Err(QrllibError::InvalidSignatureSize(_, _))
        ));
        assert!(matches!(
            get_xmss_height_from_sig_size(signature.len() as u32, 3),
            Err(QrllibError::InvalidXmssWotsParameter(3))
        ));
        assert!(matches!(
            h_msg(XmssHashFunction::Shake128, &mut [0_u8; 32], b"message", &[0_u8; 1], 32,),
            Err(QrllibError::InvalidXmssKeyLength(1))
        ));

        let odd_params =
            XmssParams::new(XMSS_WOTS_PARAM_N, 3, XMSS_WOTS_PARAM_W, 1).expect("odd-height params");
        let mut odd_bds_state = BdsState::new(3, XMSS_WOTS_PARAM_N, 1);
        let mut public_key = vec![0_u8; XMSS_PUBLIC_KEY_SIZE];
        let mut secret_key = vec![0_u8; XMSS_SECRET_KEY_SIZE];
        assert!(matches!(
            xmss_fast_gen_key_pair(
                XmssHashFunction::Shake128,
                &odd_params,
                &mut public_key,
                &mut secret_key,
                &mut odd_bds_state,
                &[0_u8; 48],
            ),
            Err(QrllibError::InvalidXmssHeight(3))
        ));

        tree.zeroize();
        assert!(tree.secret_key().iter().all(|byte| *byte == 0));
        assert!(tree.seed().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn xmss_verification_and_index_error_paths_are_covered() {
        let mut tree = Xmss::initialize_tree(
            XmssHeight::new(4).expect("height"),
            XmssHashFunction::Shake128,
            &[0_u8; 48],
        )
        .expect("tree");

        let public_key = tree.public_key();
        let signature0 = tree.sign(b"branch coverage").expect("sig0");
        let _signature1 = tree.sign(b"branch coverage").expect("sig1");
        let _signature2 = tree.sign(b"branch coverage").expect("sig2");
        let signature3 = tree.sign(b"branch coverage").expect("sig3");

        assert!(verify_xmss(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &signature3,
            &public_key,
        ));
        assert!(!verify_xmss(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &signature0[..signature0.len() - 1],
            &public_key,
        ));
        assert!(!verify_xmss(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &signature0,
            &public_key[..16],
        ));
        assert!(!verify_xmss_with_custom_wots_param_w(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &signature0,
            &public_key,
            8,
        ));
        assert!(!verify_xmss_with_custom_wots_param_w(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &signature0[..40],
            &public_key,
            XMSS_WOTS_PARAM_W,
        ));

        let mut too_long_signature = signature0.clone();
        too_long_signature.resize(signature0.len() + (usize::from(XMSS_MAX_HEIGHT) + 1) * 32, 0);
        assert!(!verify_xmss_with_custom_wots_param_w(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &too_long_signature,
            &public_key,
            XMSS_WOTS_PARAM_W,
        ));

        let height_two_signature = vec![0_u8; signature0.len() - 64];
        assert!(!verify_xmss_with_custom_wots_param_w(
            XmssHashFunction::Shake128,
            b"branch coverage",
            &height_two_signature,
            &public_key,
            XMSS_WOTS_PARAM_W,
        ));

        assert!(matches!(tree.set_index(1 << 4), Err(QrllibError::XmssOtsIndexTooHigh)));
        assert!(matches!(tree.set_index(3), Err(QrllibError::XmssOtsIndexRewind)));

        let valid_params =
            XmssParams::new(XMSS_WOTS_PARAM_N, 4, XMSS_WOTS_PARAM_W, XMSS_WOTS_PARAM_K)
                .expect("valid params");
        let mut public_key = vec![0_u8; XMSS_PUBLIC_KEY_SIZE];
        let mut secret_key = vec![0_u8; XMSS_SECRET_KEY_SIZE];
        let mut bds_state = BdsState::new(4, XMSS_WOTS_PARAM_N, XMSS_WOTS_PARAM_K);
        xmss_fast_gen_key_pair(
            XmssHashFunction::Shake128,
            &valid_params,
            &mut public_key,
            &mut secret_key,
            &mut bds_state,
            &[0_u8; 48],
        )
        .expect("generated key pair");
    }

    #[test]
    fn xmss_sign_rejects_zeroized_secret_key() {
        let mut tree = Xmss::initialize_tree(
            XmssHeight::new(4).expect("height"),
            XmssHashFunction::Shake128,
            &[0_u8; 48],
        )
        .expect("tree");
        tree.zeroize();
        assert!(matches!(tree.sign(b"after zeroize"), Err(QrllibError::XmssSecretKeyZeroized)));
    }
}
