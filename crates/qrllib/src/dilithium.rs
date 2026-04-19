use crate::{
    error::{QrllibError, Result},
    lattice::{
        D, GAMMA2, N, Q, c_add_q, decompose, inv_ntt_to_mont, make_hint, montgomery_reduce, ntt,
        power2_round, reduce32, use_hint,
    },
};
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

pub const DILITHIUM_CRYPTO_SEED_SIZE: usize = 32;
pub const DILITHIUM_PUBLIC_KEY_SIZE: usize = DILITHIUM_CRYPTO_SEED_SIZE + K * POLY_T1_PACKED_BYTES;
pub const DILITHIUM_SECRET_KEY_SIZE: usize = 2 * DILITHIUM_CRYPTO_SEED_SIZE
    + TR_BYTES
    + L * POLY_ETA_PACKED_BYTES
    + K * POLY_ETA_PACKED_BYTES
    + K * POLY_T0_PACKED_BYTES;
pub const DILITHIUM_SIGNATURE_SIZE: usize =
    DILITHIUM_CRYPTO_SEED_SIZE + L * POLY_Z_PACKED_BYTES + POLY_VEC_H_PACKED_BYTES;

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;
const STREAM128_BLOCK_BYTES: usize = SHAKE128_RATE;
const STREAM256_BLOCK_BYTES: usize = SHAKE256_RATE;

const POLY_UNIFORM_N_BLOCKS: usize = 768_usize.div_ceil(STREAM128_BLOCK_BYTES);
const POLY_UNIFORM_ETA_N_BLOCKS: usize = 136_usize.div_ceil(STREAM256_BLOCK_BYTES);
const POLY_UNIFORM_GAMMA1_N_BLOCKS: usize = POLY_Z_PACKED_BYTES.div_ceil(STREAM256_BLOCK_BYTES);

const CRH_BYTES: usize = 64;
const TR_BYTES: usize = 64;
const K: usize = 8;
const L: usize = 7;
const ETA: i32 = 2;
const TAU: usize = 60;
const BETA: i32 = 120;
const GAMMA1: i32 = 1 << 19;
const OMEGA: usize = 75;

const POLY_T1_PACKED_BYTES: usize = 320;
const POLY_T0_PACKED_BYTES: usize = 416;
const POLY_ETA_PACKED_BYTES: usize = 96;
const POLY_Z_PACKED_BYTES: usize = 640;
const POLY_VEC_H_PACKED_BYTES: usize = OMEGA + K;
const POLY_W1_PACKED_BYTES: usize = 128;

#[derive(Clone, Copy, Debug)]
struct Poly {
    coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0; N] }
    }
}

#[derive(Clone, Copy, Debug)]
struct PolyVecK {
    vec: [Poly; K],
}

impl Default for PolyVecK {
    fn default() -> Self {
        Self { vec: [Poly::default(); K] }
    }
}

#[derive(Clone, Copy, Debug)]
struct PolyVecL {
    vec: [Poly; L],
}

impl Default for PolyVecL {
    fn default() -> Self {
        Self { vec: [Poly::default(); L] }
    }
}

#[derive(Clone, Debug)]
pub struct Dilithium {
    public_key: [u8; DILITHIUM_PUBLIC_KEY_SIZE],
    secret_key: [u8; DILITHIUM_SECRET_KEY_SIZE],
    seed: [u8; DILITHIUM_CRYPTO_SEED_SIZE],
}

pub fn dilithium_extract_message(signature_message: &[u8]) -> Option<&[u8]> {
    if signature_message.len() < DILITHIUM_SIGNATURE_SIZE {
        None
    } else {
        Some(&signature_message[DILITHIUM_SIGNATURE_SIZE..])
    }
}

pub fn dilithium_extract_signature(signature_message: &[u8]) -> Option<&[u8]> {
    if signature_message.len() < DILITHIUM_SIGNATURE_SIZE {
        None
    } else {
        Some(&signature_message[..DILITHIUM_SIGNATURE_SIZE])
    }
}

pub fn validate_dilithium_public_key(public_key: &[u8]) -> Result<()> {
    if public_key.len() != DILITHIUM_PUBLIC_KEY_SIZE {
        return Err(QrllibError::InvalidDilithiumPublicKeySize(
            public_key.len(),
            DILITHIUM_PUBLIC_KEY_SIZE,
        ));
    }

    Ok(())
}

pub fn validate_dilithium_secret_key(secret_key: &[u8]) -> Result<()> {
    if secret_key.len() != DILITHIUM_SECRET_KEY_SIZE {
        return Err(QrllibError::InvalidDilithiumSecretKeySize(
            secret_key.len(),
            DILITHIUM_SECRET_KEY_SIZE,
        ));
    }

    Ok(())
}

pub fn verify_dilithium_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if validate_dilithium_public_key(public_key).is_err()
        || signature.len() != DILITHIUM_SIGNATURE_SIZE
    {
        return false;
    }

    let mut signature_bytes = [0_u8; DILITHIUM_SIGNATURE_SIZE];
    signature_bytes.copy_from_slice(signature);
    let mut public_key_bytes = [0_u8; DILITHIUM_PUBLIC_KEY_SIZE];
    public_key_bytes.copy_from_slice(public_key);
    crypto_sign_verify(&signature_bytes, message, &public_key_bytes)
}

pub fn dilithium_open(signature_message: &[u8], public_key: &[u8]) -> Option<Vec<u8>> {
    if validate_dilithium_public_key(public_key).is_err()
        || signature_message.len() < DILITHIUM_SIGNATURE_SIZE
    {
        return None;
    }

    let mut public_key_bytes = [0_u8; DILITHIUM_PUBLIC_KEY_SIZE];
    public_key_bytes.copy_from_slice(public_key);
    crypto_sign_open(signature_message, &public_key_bytes)
}

pub fn sign_dilithium_with_secret_key(
    message: &[u8],
    secret_key: &[u8],
) -> Result<[u8; DILITHIUM_SIGNATURE_SIZE]> {
    validate_dilithium_secret_key(secret_key)?;
    if secret_key.iter().all(|byte| *byte == 0) {
        return Err(QrllibError::DilithiumSecretKeyZeroized);
    }

    let mut secret_key_bytes = [0_u8; DILITHIUM_SECRET_KEY_SIZE];
    secret_key_bytes.copy_from_slice(secret_key);
    let mut signature = [0_u8; DILITHIUM_SIGNATURE_SIZE];
    crypto_sign_signature(&mut signature, message, &secret_key_bytes, false)?;
    Ok(signature)
}

impl Dilithium {
    pub fn generate() -> Result<Self> {
        let mut seed = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
        getrandom::getrandom(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; DILITHIUM_CRYPTO_SEED_SIZE]) -> Self {
        let mut hashed_seed = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
        shake256(&mut hashed_seed, &seed);

        let mut public_key = [0_u8; DILITHIUM_PUBLIC_KEY_SIZE];
        let mut secret_key = [0_u8; DILITHIUM_SECRET_KEY_SIZE];
        crypto_sign_keypair(&hashed_seed, &mut public_key, &mut secret_key);

        Self { public_key, secret_key, seed }
    }

    pub fn from_hex_seed(value: &str) -> Result<Self> {
        let value = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
        let seed = hex::decode(value)?;
        if seed.len() != DILITHIUM_CRYPTO_SEED_SIZE {
            return Err(QrllibError::InvalidDilithiumSeedSize(
                seed.len(),
                DILITHIUM_CRYPTO_SEED_SIZE,
            ));
        }

        let mut seed_bytes = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
        seed_bytes.copy_from_slice(&seed);
        Ok(Self::from_seed(seed_bytes))
    }

    pub fn public_key_bytes(&self) -> [u8; DILITHIUM_PUBLIC_KEY_SIZE] {
        self.public_key
    }

    pub fn secret_key_bytes(&self) -> [u8; DILITHIUM_SECRET_KEY_SIZE] {
        self.secret_key
    }

    pub fn seed(&self) -> [u8; DILITHIUM_CRYPTO_SEED_SIZE] {
        self.seed
    }

    pub fn hex_seed(&self) -> String {
        format!("0x{}", hex::encode(self.seed))
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; DILITHIUM_SIGNATURE_SIZE]> {
        sign_dilithium_with_secret_key(message, &self.secret_key)
    }

    pub fn seal(&self, message: &[u8]) -> Result<Vec<u8>> {
        crypto_sign(message, &self.secret_key, false)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; DILITHIUM_SIGNATURE_SIZE]) -> bool {
        crypto_sign_verify(signature, message, &self.public_key)
    }

    pub fn zeroize(&mut self) {
        self.secret_key.zeroize();
        self.seed.zeroize();
    }
}

fn shake256(output: &mut [u8], input: &[u8]) {
    let mut state = Shake256::default();
    state.update(input);
    let mut reader = state.finalize_xof();
    reader.read(output);
}

fn shake256_many(output: &mut [u8], inputs: &[&[u8]]) {
    let mut state = Shake256::default();
    for input in inputs {
        state.update(input);
    }
    let mut reader = state.finalize_xof();
    reader.read(output);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (lhs, rhs) in left.iter().zip(right) {
        diff |= lhs ^ rhs;
    }

    diff == 0
}

fn zero_poly(poly: &mut Poly) {
    poly.coeffs.zeroize();
}

fn zero_poly_vec_l(vector: &mut PolyVecL) {
    for poly in &mut vector.vec {
        zero_poly(poly);
    }
}

fn zero_poly_vec_k(vector: &mut PolyVecK) {
    for poly in &mut vector.vec {
        zero_poly(poly);
    }
}

fn poly_c_add_q(poly: &mut Poly) {
    for coefficient in &mut poly.coeffs {
        *coefficient = c_add_q(*coefficient);
    }
}

fn poly_reduce(poly: &mut Poly) {
    for coefficient in &mut poly.coeffs {
        *coefficient = reduce32(*coefficient);
    }
}

fn poly_add(out: &mut Poly, left: &Poly, right: &Poly) {
    for index in 0..N {
        out.coeffs[index] = left.coeffs[index].wrapping_add(right.coeffs[index]);
    }
}

fn poly_sub(out: &mut Poly, left: &Poly, right: &Poly) {
    for index in 0..N {
        out.coeffs[index] = left.coeffs[index].wrapping_sub(right.coeffs[index]);
    }
}

fn poly_shift_l(poly: &mut Poly) {
    for coefficient in &mut poly.coeffs {
        *coefficient = coefficient.wrapping_shl(D as u32);
    }
}

fn poly_ntt(poly: &mut Poly) {
    ntt(&mut poly.coeffs);
}

fn poly_inv_ntt_to_mont(poly: &mut Poly) {
    inv_ntt_to_mont(&mut poly.coeffs);
}

fn poly_point_wise_montgomery(out: &mut Poly, left: &Poly, right: &Poly) {
    for index in 0..N {
        out.coeffs[index] =
            montgomery_reduce(i64::from(left.coeffs[index]) * i64::from(right.coeffs[index]));
    }
}

fn poly_power2_round(high: &mut Poly, low: &mut Poly, input: &Poly) {
    for index in 0..N {
        high.coeffs[index] = power2_round(&mut low.coeffs[index], input.coeffs[index]);
    }
}

fn poly_decompose(high: &mut Poly, low: &mut Poly, input: &Poly) {
    for index in 0..N {
        high.coeffs[index] = decompose(&mut low.coeffs[index], input.coeffs[index]);
    }
}

fn poly_make_hint(hints: &mut Poly, low: &Poly, high: &Poly) -> usize {
    let mut sum = 0_usize;
    for index in 0..N {
        hints.coeffs[index] = make_hint(low.coeffs[index], high.coeffs[index]) as i32;
        sum += hints.coeffs[index] as usize;
    }
    sum
}

fn poly_use_hint(out: &mut Poly, input: &Poly, hints: &Poly) {
    for index in 0..N {
        out.coeffs[index] = use_hint(input.coeffs[index], hints.coeffs[index]);
    }
}

fn poly_chk_norm(poly: &Poly, bound: i32) -> i32 {
    if bound > (Q - 1) / 8 {
        return 1;
    }

    let mut violation = 0_i32;
    for coefficient in poly.coeffs {
        let sign = coefficient >> 31;
        let absolute = coefficient.wrapping_sub(sign & coefficient.wrapping_mul(2));
        violation |= bound.wrapping_sub(1).wrapping_sub(absolute) >> 31;
    }

    ((violation as u32) >> 31) as i32
}

fn poly_uniform(poly: &mut Poly, seed: &[u8; DILITHIUM_CRYPTO_SEED_SIZE], nonce: u16) {
    let mut buffer = [0_u8; POLY_UNIFORM_N_BLOCKS * STREAM128_BLOCK_BYTES + 2];
    let mut buffer_len = POLY_UNIFORM_N_BLOCKS * STREAM128_BLOCK_BYTES;

    let mut state = Shake128::default();
    state.update(seed);
    state.update(&nonce.to_le_bytes());
    let mut reader = state.finalize_xof();
    reader.read(&mut buffer[..buffer_len]);

    let mut ctr = rej_uniform(&mut poly.coeffs, &buffer[..buffer_len]);
    while ctr < N {
        let off = buffer_len % 3;
        buffer.copy_within(buffer_len - off..buffer_len, 0);
        reader.read(&mut buffer[off..off + STREAM128_BLOCK_BYTES]);
        buffer_len = STREAM128_BLOCK_BYTES + off;
        ctr += rej_uniform(&mut poly.coeffs[ctr..], &buffer[..buffer_len]);
    }
}

fn rej_uniform(coefficients: &mut [i32], buffer: &[u8]) -> usize {
    let mut ctr = 0_usize;
    let mut pos = 0_usize;

    while ctr < coefficients.len() && pos + 3 <= buffer.len() {
        let mut t = u32::from(buffer[pos]);
        t |= u32::from(buffer[pos + 1]) << 8;
        t |= u32::from(buffer[pos + 2]) << 16;
        t &= 0x7f_ffff;
        pos += 3;

        if t < Q as u32 {
            coefficients[ctr] = t as i32;
            ctr += 1;
        }
    }

    ctr
}

fn rej_eta(coefficients: &mut [i32], buffer: &[u8]) -> usize {
    let mut ctr = 0_usize;
    let mut pos = 0_usize;

    while ctr < coefficients.len() && pos < buffer.len() {
        let mut t0 = u32::from(buffer[pos] & 0x0f);
        let mut t1 = u32::from(buffer[pos] >> 4);
        pos += 1;

        if t0 < 15 {
            t0 -= ((205 * t0) >> 10) * 5;
            coefficients[ctr] = ETA - t0 as i32;
            ctr += 1;
        }

        if t1 < 15 && ctr < coefficients.len() {
            t1 -= ((205 * t1) >> 10) * 5;
            coefficients[ctr] = ETA - t1 as i32;
            ctr += 1;
        }
    }

    ctr
}

fn poly_uniform_eta(poly: &mut Poly, seed: &[u8; CRH_BYTES], nonce: u16) {
    let mut buffer = [0_u8; POLY_UNIFORM_ETA_N_BLOCKS * STREAM256_BLOCK_BYTES];
    let mut state = Shake256::default();
    state.update(seed);
    state.update(&nonce.to_le_bytes());
    let mut reader = state.finalize_xof();
    reader.read(&mut buffer);

    let mut ctr = rej_eta(&mut poly.coeffs, &buffer);
    while ctr < N {
        reader.read(&mut buffer[..STREAM256_BLOCK_BYTES]);
        ctr += rej_eta(&mut poly.coeffs[ctr..], &buffer[..STREAM256_BLOCK_BYTES]);
    }
}

fn poly_uniform_gamma1(poly: &mut Poly, seed: &[u8; CRH_BYTES], nonce: u16) {
    let mut buffer = [0_u8; POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM256_BLOCK_BYTES];
    let mut state = Shake256::default();
    state.update(seed);
    state.update(&nonce.to_le_bytes());
    let mut reader = state.finalize_xof();
    reader.read(&mut buffer);
    poly_z_unpack(poly, &buffer);
}

fn poly_challenge(challenge: &mut Poly, seed: &[u8; DILITHIUM_CRYPTO_SEED_SIZE]) {
    let mut buffer = [0_u8; SHAKE256_RATE];
    let mut state = Shake256::default();
    state.update(seed);
    let mut reader = state.finalize_xof();
    reader.read(&mut buffer);

    let mut signs = 0_u64;
    for (index, byte) in buffer.iter().take(8).enumerate() {
        signs |= u64::from(*byte) << (8 * index);
    }

    challenge.coeffs.fill(0);
    let mut pos = 8_usize;
    for index in (N - TAU)..N {
        let selected = loop {
            if pos >= SHAKE256_RATE {
                reader.read(&mut buffer);
                pos = 0;
            }

            let byte = usize::from(buffer[pos]);
            pos += 1;
            if byte <= index {
                break byte;
            }
        };

        challenge.coeffs[index] = challenge.coeffs[selected];
        challenge.coeffs[selected] = 1 - 2 * (signs & 1) as i32;
        signs >>= 1;
    }
}

fn poly_eta_pack(output: &mut [u8], poly: &Poly) {
    let mut t = [0_u8; 8];

    for index in 0..(N / 8) {
        for (inner, value) in t.iter_mut().enumerate() {
            *value = (ETA - poly.coeffs[8 * index + inner]) as u8;
        }

        output[3 * index] = t[0] | (t[1] << 3) | (t[2] << 6);
        output[3 * index + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        output[3 * index + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}

fn poly_eta_unpack(output: &mut Poly, input: &[u8]) {
    for index in 0..(N / 8) {
        output.coeffs[8 * index] = ETA - i32::from((input[3 * index]) & 7);
        output.coeffs[8 * index + 1] = ETA - i32::from((input[3 * index] >> 3) & 7);
        output.coeffs[8 * index + 2] =
            ETA - i32::from(((input[3 * index] >> 6) | (input[3 * index + 1] << 2)) & 7);
        output.coeffs[8 * index + 3] = ETA - i32::from((input[3 * index + 1] >> 1) & 7);
        output.coeffs[8 * index + 4] = ETA - i32::from((input[3 * index + 1] >> 4) & 7);
        output.coeffs[8 * index + 5] =
            ETA - i32::from(((input[3 * index + 1] >> 7) | (input[3 * index + 2] << 1)) & 7);
        output.coeffs[8 * index + 6] = ETA - i32::from((input[3 * index + 2] >> 2) & 7);
        output.coeffs[8 * index + 7] = ETA - i32::from((input[3 * index + 2] >> 5) & 7);
    }
}

fn poly_t1_pack(output: &mut [u8], poly: &Poly) {
    for index in 0..(N / 4) {
        let c0 = poly.coeffs[4 * index] as u32;
        let c1 = poly.coeffs[4 * index + 1] as u32;
        let c2 = poly.coeffs[4 * index + 2] as u32;
        let c3 = poly.coeffs[4 * index + 3] as u32;

        output[5 * index] = c0 as u8;
        output[5 * index + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
        output[5 * index + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
        output[5 * index + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
        output[5 * index + 4] = (c3 >> 2) as u8;
    }
}

fn poly_t1_unpack(output: &mut Poly, input: &[u8]) {
    for index in 0..(N / 4) {
        output.coeffs[4 * index] =
            ((u32::from(input[5 * index]) | (u32::from(input[5 * index + 1]) << 8)) & 0x3ff) as i32;
        output.coeffs[4 * index + 1] = ((u32::from(input[5 * index + 1] >> 2)
            | (u32::from(input[5 * index + 2]) << 6))
            & 0x3ff) as i32;
        output.coeffs[4 * index + 2] = ((u32::from(input[5 * index + 2] >> 4)
            | (u32::from(input[5 * index + 3]) << 4))
            & 0x3ff) as i32;
        output.coeffs[4 * index + 3] = ((u32::from(input[5 * index + 3] >> 6)
            | (u32::from(input[5 * index + 4]) << 2))
            & 0x3ff) as i32;
    }
}

fn poly_t0_pack(output: &mut [u8], poly: &Poly) {
    let mut t = [0_u32; 8];

    for index in 0..(N / 8) {
        for (inner, value) in t.iter_mut().enumerate() {
            *value = ((1 << (D - 1)) - poly.coeffs[8 * index + inner]) as u32;
        }

        output[13 * index] = t[0] as u8;
        output[13 * index + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
        output[13 * index + 2] = (t[1] >> 3) as u8;
        output[13 * index + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
        output[13 * index + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
        output[13 * index + 5] = (t[3] >> 1) as u8;
        output[13 * index + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
        output[13 * index + 7] = (t[4] >> 4) as u8;
        output[13 * index + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
        output[13 * index + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
        output[13 * index + 10] = (t[6] >> 2) as u8;
        output[13 * index + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
        output[13 * index + 12] = (t[7] >> 5) as u8;
    }
}

fn poly_t0_unpack(output: &mut Poly, input: &[u8]) {
    for index in 0..(N / 8) {
        output.coeffs[8 * index] = (u32::from(input[13 * index])
            | (u32::from(input[13 * index + 1]) << 8)) as i32
            & 0x1fff;

        output.coeffs[8 * index + 1] = (u32::from(input[13 * index + 1] >> 5)
            | (u32::from(input[13 * index + 2]) << 3)
            | (u32::from(input[13 * index + 3]) << 11))
            as i32
            & 0x1fff;

        output.coeffs[8 * index + 2] = (u32::from(input[13 * index + 3] >> 2)
            | (u32::from(input[13 * index + 4]) << 6))
            as i32
            & 0x1fff;

        output.coeffs[8 * index + 3] = (u32::from(input[13 * index + 4] >> 7)
            | (u32::from(input[13 * index + 5]) << 1)
            | (u32::from(input[13 * index + 6]) << 9))
            as i32
            & 0x1fff;

        output.coeffs[8 * index + 4] = (u32::from(input[13 * index + 6] >> 4)
            | (u32::from(input[13 * index + 7]) << 4)
            | (u32::from(input[13 * index + 8]) << 12))
            as i32
            & 0x1fff;

        output.coeffs[8 * index + 5] = (u32::from(input[13 * index + 8] >> 1)
            | (u32::from(input[13 * index + 9]) << 7))
            as i32
            & 0x1fff;

        output.coeffs[8 * index + 6] = (u32::from(input[13 * index + 9] >> 6)
            | (u32::from(input[13 * index + 10]) << 2)
            | (u32::from(input[13 * index + 11]) << 10))
            as i32
            & 0x1fff;

        output.coeffs[8 * index + 7] = (u32::from(input[13 * index + 11] >> 3)
            | (u32::from(input[13 * index + 12]) << 5))
            as i32
            & 0x1fff;

        for inner in 0..8 {
            output.coeffs[8 * index + inner] = (1 << (D - 1)) - output.coeffs[8 * index + inner];
        }
    }
}

fn poly_z_pack(output: &mut [u8], poly: &Poly) {
    for index in 0..(N / 2) {
        let t0 = (GAMMA1 - poly.coeffs[2 * index]) as u32;
        let t1 = (GAMMA1 - poly.coeffs[2 * index + 1]) as u32;

        output[5 * index] = t0 as u8;
        output[5 * index + 1] = (t0 >> 8) as u8;
        output[5 * index + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
        output[5 * index + 3] = (t1 >> 4) as u8;
        output[5 * index + 4] = (t1 >> 12) as u8;
    }
}

fn poly_z_unpack(output: &mut Poly, input: &[u8]) {
    for index in 0..(N / 2) {
        output.coeffs[2 * index] = (u32::from(input[5 * index])
            | (u32::from(input[5 * index + 1]) << 8)
            | (u32::from(input[5 * index + 2]) << 16)) as i32
            & 0x0f_ffff;

        output.coeffs[2 * index + 1] = (u32::from(input[5 * index + 2] >> 4)
            | (u32::from(input[5 * index + 3]) << 4)
            | (u32::from(input[5 * index + 4]) << 12))
            as i32;

        output.coeffs[2 * index] = GAMMA1 - output.coeffs[2 * index];
        output.coeffs[2 * index + 1] = GAMMA1 - output.coeffs[2 * index + 1];
    }
}

fn poly_w1_pack(output: &mut [u8], poly: &Poly) {
    for (index, byte) in output.iter_mut().enumerate().take(N / 2) {
        *byte = poly.coeffs[2 * index] as u8 | ((poly.coeffs[2 * index + 1] as u8) << 4);
    }
}

fn poly_vec_l_uniform_gamma1(vector: &mut PolyVecL, seed: &[u8; CRH_BYTES], nonce: u16) {
    for index in 0..L {
        poly_uniform_gamma1(
            &mut vector.vec[index],
            seed,
            (L as u16).wrapping_mul(nonce).wrapping_add(index as u16),
        );
    }
}

fn poly_vec_l_reduce(vector: &mut PolyVecL) {
    for poly in &mut vector.vec {
        poly_reduce(poly);
    }
}

fn poly_vec_l_add(out: &mut PolyVecL, left: &PolyVecL, right: &PolyVecL) {
    for index in 0..L {
        poly_add(&mut out.vec[index], &left.vec[index], &right.vec[index]);
    }
}

fn poly_vec_l_ntt(vector: &mut PolyVecL) {
    for poly in &mut vector.vec {
        poly_ntt(poly);
    }
}

fn poly_vec_l_inv_ntt_to_mont(vector: &mut PolyVecL) {
    for poly in &mut vector.vec {
        poly_inv_ntt_to_mont(poly);
    }
}

fn poly_vec_l_point_wise_poly_montgomery(out: &mut PolyVecL, poly: &Poly, vector: &PolyVecL) {
    for index in 0..L {
        poly_point_wise_montgomery(&mut out.vec[index], poly, &vector.vec[index]);
    }
}

fn poly_vec_matrix_expand(matrix: &mut [PolyVecL; K], rho: &[u8; DILITHIUM_CRYPTO_SEED_SIZE]) {
    for (row_index, row) in matrix.iter_mut().enumerate() {
        for column_index in 0..L {
            poly_uniform(
                &mut row.vec[column_index],
                rho,
                ((row_index as u16) << 8).wrapping_add(column_index as u16),
            );
        }
    }
}

fn poly_vec_l_chk_norm(vector: &PolyVecL, bound: i32) -> i32 {
    for poly in &vector.vec {
        if poly_chk_norm(poly, bound) != 0 {
            return 1;
        }
    }

    0
}

fn poly_vec_k_add(out: &mut PolyVecK, left: &PolyVecK, right: &PolyVecK) {
    for index in 0..K {
        poly_add(&mut out.vec[index], &left.vec[index], &right.vec[index]);
    }
}

fn poly_vec_k_sub(out: &mut PolyVecK, left: &PolyVecK, right: &PolyVecK) {
    for index in 0..K {
        poly_sub(&mut out.vec[index], &left.vec[index], &right.vec[index]);
    }
}

fn poly_vec_k_shift_l(vector: &mut PolyVecK) {
    for poly in &mut vector.vec {
        poly_shift_l(poly);
    }
}

fn poly_vec_k_ntt(vector: &mut PolyVecK) {
    for poly in &mut vector.vec {
        poly_ntt(poly);
    }
}

fn poly_vec_k_inv_ntt_to_mont(vector: &mut PolyVecK) {
    for poly in &mut vector.vec {
        poly_inv_ntt_to_mont(poly);
    }
}

fn poly_vec_k_point_wise_poly_montgomery(out: &mut PolyVecK, poly: &Poly, vector: &PolyVecK) {
    for index in 0..K {
        poly_point_wise_montgomery(&mut out.vec[index], poly, &vector.vec[index]);
    }
}

fn poly_vec_k_chk_norm(vector: &PolyVecK, bound: i32) -> i32 {
    for poly in &vector.vec {
        if poly_chk_norm(poly, bound) != 0 {
            return 1;
        }
    }

    0
}

fn poly_vec_k_power2_round(high: &mut PolyVecK, low: &mut PolyVecK, input: &PolyVecK) {
    for index in 0..K {
        poly_power2_round(&mut high.vec[index], &mut low.vec[index], &input.vec[index]);
    }
}

fn poly_vec_k_decompose(high: &mut PolyVecK, low: &mut PolyVecK, input: &PolyVecK) {
    for index in 0..K {
        poly_decompose(&mut high.vec[index], &mut low.vec[index], &input.vec[index]);
    }
}

fn poly_vec_k_make_hint(hints: &mut PolyVecK, low: &PolyVecK, high: &PolyVecK) -> usize {
    let mut sum = 0_usize;
    for index in 0..K {
        sum += poly_make_hint(&mut hints.vec[index], &low.vec[index], &high.vec[index]);
    }
    sum
}

fn poly_vec_k_use_hint(out: &mut PolyVecK, input: &PolyVecK, hints: &PolyVecK) {
    for index in 0..K {
        poly_use_hint(&mut out.vec[index], &input.vec[index], &hints.vec[index]);
    }
}

fn poly_vec_l_point_wise_acc_montgomery(out: &mut Poly, left: &PolyVecL, right: &PolyVecL) {
    let mut temporary = Poly::default();
    poly_point_wise_montgomery(out, &left.vec[0], &right.vec[0]);
    for index in 1..L {
        poly_point_wise_montgomery(&mut temporary, &left.vec[index], &right.vec[index]);
        let current = *out;
        poly_add(out, &current, &temporary);
    }
}

fn poly_vec_matrix_point_wise_montgomery(
    out: &mut PolyVecK,
    matrix: &[PolyVecL; K],
    vector: &PolyVecL,
) {
    for (index, row) in matrix.iter().enumerate().take(K) {
        poly_vec_l_point_wise_acc_montgomery(&mut out.vec[index], row, vector);
    }
}

fn poly_vec_l_uniform_eta(vector: &mut PolyVecL, seed: &[u8; CRH_BYTES], mut nonce: u16) {
    for poly in &mut vector.vec {
        poly_uniform_eta(poly, seed, nonce);
        nonce = nonce.wrapping_add(1);
    }
}

fn poly_vec_k_uniform_eta(vector: &mut PolyVecK, seed: &[u8; CRH_BYTES], mut nonce: u16) {
    for poly in &mut vector.vec {
        poly_uniform_eta(poly, seed, nonce);
        nonce = nonce.wrapping_add(1);
    }
}

fn poly_vec_k_reduce(vector: &mut PolyVecK) {
    for poly in &mut vector.vec {
        poly_reduce(poly);
    }
}

fn poly_vec_k_cadd_q(vector: &mut PolyVecK) {
    for poly in &mut vector.vec {
        poly_c_add_q(poly);
    }
}

fn poly_vec_k_pack_w1(output: &mut [u8; K * POLY_W1_PACKED_BYTES], input: &PolyVecK) {
    for index in 0..K {
        poly_w1_pack(
            &mut output[index * POLY_W1_PACKED_BYTES..(index + 1) * POLY_W1_PACKED_BYTES],
            &input.vec[index],
        );
    }
}

fn pack_pk(
    public_key: &mut [u8; DILITHIUM_PUBLIC_KEY_SIZE],
    rho: &[u8; DILITHIUM_CRYPTO_SEED_SIZE],
    t1: &PolyVecK,
) {
    public_key[..DILITHIUM_CRYPTO_SEED_SIZE].copy_from_slice(rho);
    let mut offset = DILITHIUM_CRYPTO_SEED_SIZE;
    for poly in &t1.vec {
        poly_t1_pack(&mut public_key[offset..offset + POLY_T1_PACKED_BYTES], poly);
        offset += POLY_T1_PACKED_BYTES;
    }
}

fn unpack_pk(
    rho: &mut [u8; DILITHIUM_CRYPTO_SEED_SIZE],
    t1: &mut PolyVecK,
    public_key: &[u8; DILITHIUM_PUBLIC_KEY_SIZE],
) {
    rho.copy_from_slice(&public_key[..DILITHIUM_CRYPTO_SEED_SIZE]);
    let mut offset = DILITHIUM_CRYPTO_SEED_SIZE;
    for poly in &mut t1.vec {
        poly_t1_unpack(poly, &public_key[offset..offset + POLY_T1_PACKED_BYTES]);
        offset += POLY_T1_PACKED_BYTES;
    }
}

fn pack_sk(
    secret_key: &mut [u8; DILITHIUM_SECRET_KEY_SIZE],
    rho: &[u8; DILITHIUM_CRYPTO_SEED_SIZE],
    tr: &[u8; TR_BYTES],
    key: &[u8; DILITHIUM_CRYPTO_SEED_SIZE],
    t0: &PolyVecK,
    s1: &PolyVecL,
    s2: &PolyVecK,
) {
    secret_key[..DILITHIUM_CRYPTO_SEED_SIZE].copy_from_slice(rho);
    secret_key[DILITHIUM_CRYPTO_SEED_SIZE..2 * DILITHIUM_CRYPTO_SEED_SIZE].copy_from_slice(key);
    secret_key[2 * DILITHIUM_CRYPTO_SEED_SIZE..2 * DILITHIUM_CRYPTO_SEED_SIZE + TR_BYTES]
        .copy_from_slice(tr);

    let mut offset = 2 * DILITHIUM_CRYPTO_SEED_SIZE + TR_BYTES;
    for poly in &s1.vec {
        poly_eta_pack(&mut secret_key[offset..offset + POLY_ETA_PACKED_BYTES], poly);
        offset += POLY_ETA_PACKED_BYTES;
    }
    for poly in &s2.vec {
        poly_eta_pack(&mut secret_key[offset..offset + POLY_ETA_PACKED_BYTES], poly);
        offset += POLY_ETA_PACKED_BYTES;
    }
    for poly in &t0.vec {
        poly_t0_pack(&mut secret_key[offset..offset + POLY_T0_PACKED_BYTES], poly);
        offset += POLY_T0_PACKED_BYTES;
    }
}

fn unpack_sk(
    rho: &mut [u8; DILITHIUM_CRYPTO_SEED_SIZE],
    key: &mut [u8; DILITHIUM_CRYPTO_SEED_SIZE],
    tr: &mut [u8; TR_BYTES],
    t0: &mut PolyVecK,
    s1: &mut PolyVecL,
    s2: &mut PolyVecK,
    secret_key: &[u8; DILITHIUM_SECRET_KEY_SIZE],
) {
    rho.copy_from_slice(&secret_key[..DILITHIUM_CRYPTO_SEED_SIZE]);
    key.copy_from_slice(&secret_key[DILITHIUM_CRYPTO_SEED_SIZE..2 * DILITHIUM_CRYPTO_SEED_SIZE]);
    tr.copy_from_slice(
        &secret_key[2 * DILITHIUM_CRYPTO_SEED_SIZE..2 * DILITHIUM_CRYPTO_SEED_SIZE + TR_BYTES],
    );

    let mut offset = 2 * DILITHIUM_CRYPTO_SEED_SIZE + TR_BYTES;
    for poly in &mut s1.vec {
        poly_eta_unpack(poly, &secret_key[offset..offset + POLY_ETA_PACKED_BYTES]);
        offset += POLY_ETA_PACKED_BYTES;
    }
    for poly in &mut s2.vec {
        poly_eta_unpack(poly, &secret_key[offset..offset + POLY_ETA_PACKED_BYTES]);
        offset += POLY_ETA_PACKED_BYTES;
    }
    for poly in &mut t0.vec {
        poly_t0_unpack(poly, &secret_key[offset..offset + POLY_T0_PACKED_BYTES]);
        offset += POLY_T0_PACKED_BYTES;
    }
}

fn pack_sig(
    signature: &mut [u8; DILITHIUM_SIGNATURE_SIZE],
    challenge: &[u8; DILITHIUM_CRYPTO_SEED_SIZE],
    z: &PolyVecL,
    hints: &PolyVecK,
) {
    signature[..DILITHIUM_CRYPTO_SEED_SIZE].copy_from_slice(challenge);
    let mut offset = DILITHIUM_CRYPTO_SEED_SIZE;
    for poly in &z.vec {
        poly_z_pack(&mut signature[offset..offset + POLY_Z_PACKED_BYTES], poly);
        offset += POLY_Z_PACKED_BYTES;
    }

    for byte in &mut signature[offset..] {
        *byte = 0;
    }

    let mut hint_count = 0_usize;
    for poly_index in 0..K {
        for coefficient_index in 0..N {
            if hints.vec[poly_index].coeffs[coefficient_index] != 0 {
                signature[offset + hint_count] = coefficient_index as u8;
                hint_count += 1;
            }
            signature[offset + OMEGA + poly_index] = hint_count as u8;
        }
    }
}

fn unpack_sig(
    challenge: &mut [u8; DILITHIUM_CRYPTO_SEED_SIZE],
    z: &mut PolyVecL,
    hints: &mut PolyVecK,
    signature: &[u8; DILITHIUM_SIGNATURE_SIZE],
) -> bool {
    challenge.copy_from_slice(&signature[..DILITHIUM_CRYPTO_SEED_SIZE]);
    let mut offset = DILITHIUM_CRYPTO_SEED_SIZE;
    for poly in &mut z.vec {
        poly_z_unpack(poly, &signature[offset..offset + POLY_Z_PACKED_BYTES]);
        offset += POLY_Z_PACKED_BYTES;
    }

    let mut hint_count = 0_usize;
    for poly_index in 0..K {
        hints.vec[poly_index].coeffs.fill(0);
        let next_hint_count = usize::from(signature[offset + OMEGA + poly_index]);
        if next_hint_count < hint_count || next_hint_count > OMEGA {
            return true;
        }

        for position in hint_count..next_hint_count {
            if position > hint_count
                && signature[offset + position] <= signature[offset + position - 1]
            {
                return true;
            }
            hints.vec[poly_index].coeffs[usize::from(signature[offset + position])] = 1;
        }

        hint_count = next_hint_count;
    }

    for byte in &signature[offset + hint_count..offset + OMEGA] {
        if *byte != 0 {
            return true;
        }
    }

    false
}

fn crypto_sign_keypair(
    seed: &[u8; DILITHIUM_CRYPTO_SEED_SIZE],
    public_key: &mut [u8; DILITHIUM_PUBLIC_KEY_SIZE],
    secret_key: &mut [u8; DILITHIUM_SECRET_KEY_SIZE],
) {
    let mut tr = [0_u8; TR_BYTES];
    let mut rho = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut key = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut rho_prime = [0_u8; CRH_BYTES];

    let mut matrix = [PolyVecL::default(); K];
    let mut s1 = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    let mut t1 = PolyVecK::default();
    let mut t0 = PolyVecK::default();

    let mut state = Shake256::default();
    state.update(seed);
    let mut reader = state.finalize_xof();
    reader.read(&mut rho);
    reader.read(&mut rho_prime);
    reader.read(&mut key);

    poly_vec_matrix_expand(&mut matrix, &rho);
    poly_vec_l_uniform_eta(&mut s1, &rho_prime, 0);
    poly_vec_k_uniform_eta(&mut s2, &rho_prime, L as u16);

    let mut s1hat = s1;
    poly_vec_l_ntt(&mut s1hat);
    poly_vec_matrix_point_wise_montgomery(&mut t1, &matrix, &s1hat);
    poly_vec_k_reduce(&mut t1);
    poly_vec_k_inv_ntt_to_mont(&mut t1);

    let current_t1 = t1;
    poly_vec_k_add(&mut t1, &current_t1, &s2);
    poly_vec_k_cadd_q(&mut t1);
    let rounded_t = t1;
    poly_vec_k_power2_round(&mut t1, &mut t0, &rounded_t);
    pack_pk(public_key, &rho, &t1);

    shake256(&mut tr, public_key);
    pack_sk(secret_key, &rho, &tr, &key, &t0, &s1, &s2);
}

fn crypto_sign_signature(
    signature: &mut [u8; DILITHIUM_SIGNATURE_SIZE],
    message: &[u8],
    secret_key: &[u8; DILITHIUM_SECRET_KEY_SIZE],
    randomized_signing: bool,
) -> Result<()> {
    let mut rho = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut key = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut tr = [0_u8; TR_BYTES];
    let mut mu = [0_u8; CRH_BYTES];
    let mut rho_prime = [0_u8; CRH_BYTES];
    let mut s1 = PolyVecL::default();
    let mut y = PolyVecL::default();
    let mut z = PolyVecL::default();
    let mut matrix = [PolyVecL::default(); K];
    let mut s2 = PolyVecK::default();
    let mut t0 = PolyVecK::default();
    let mut w1 = PolyVecK::default();
    let mut hints = PolyVecK::default();
    let mut w0 = PolyVecK::default();
    let mut challenge_poly = Poly::default();
    let mut nonce = 0_u16;

    unpack_sk(&mut rho, &mut key, &mut tr, &mut t0, &mut s1, &mut s2, secret_key);

    let result = (|| -> Result<()> {
        shake256_many(&mut mu, &[&tr, message]);

        if randomized_signing {
            getrandom::getrandom(&mut rho_prime)?;
        } else {
            let mut data_to_be_hashed = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE + CRH_BYTES];
            data_to_be_hashed[..DILITHIUM_CRYPTO_SEED_SIZE].copy_from_slice(&key);
            data_to_be_hashed[DILITHIUM_CRYPTO_SEED_SIZE..].copy_from_slice(&mu);
            shake256(&mut rho_prime, &data_to_be_hashed);
            data_to_be_hashed.zeroize();
        }

        poly_vec_matrix_expand(&mut matrix, &rho);
        poly_vec_l_ntt(&mut s1);
        poly_vec_k_ntt(&mut s2);
        poly_vec_k_ntt(&mut t0);

        loop {
            poly_vec_l_uniform_gamma1(&mut y, &rho_prime, nonce);
            nonce = nonce.wrapping_add(1);

            z = y;
            poly_vec_l_ntt(&mut z);
            poly_vec_matrix_point_wise_montgomery(&mut w1, &matrix, &z);
            poly_vec_k_reduce(&mut w1);
            poly_vec_k_inv_ntt_to_mont(&mut w1);

            poly_vec_k_cadd_q(&mut w1);
            let decomposed_w = w1;
            poly_vec_k_decompose(&mut w1, &mut w0, &decomposed_w);

            let mut packed_w1 = [0_u8; K * POLY_W1_PACKED_BYTES];
            poly_vec_k_pack_w1(&mut packed_w1, &w1);
            shake256_many(&mut signature[..DILITHIUM_CRYPTO_SEED_SIZE], &[&mu, &packed_w1]);
            let mut challenge = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
            challenge.copy_from_slice(&signature[..DILITHIUM_CRYPTO_SEED_SIZE]);
            poly_challenge(&mut challenge_poly, &challenge);
            poly_ntt(&mut challenge_poly);

            poly_vec_l_point_wise_poly_montgomery(&mut z, &challenge_poly, &s1);
            poly_vec_l_inv_ntt_to_mont(&mut z);
            let z_current = z;
            poly_vec_l_add(&mut z, &z_current, &y);
            poly_vec_l_reduce(&mut z);
            if poly_vec_l_chk_norm(&z, GAMMA1 - BETA) != 0 {
                continue;
            }

            poly_vec_k_point_wise_poly_montgomery(&mut hints, &challenge_poly, &s2);
            poly_vec_k_inv_ntt_to_mont(&mut hints);
            let w0_current = w0;
            poly_vec_k_sub(&mut w0, &w0_current, &hints);
            poly_vec_k_reduce(&mut w0);
            if poly_vec_k_chk_norm(&w0, GAMMA2 - BETA) != 0 {
                continue;
            }

            poly_vec_k_point_wise_poly_montgomery(&mut hints, &challenge_poly, &t0);
            poly_vec_k_inv_ntt_to_mont(&mut hints);
            poly_vec_k_reduce(&mut hints);
            if poly_vec_k_chk_norm(&hints, GAMMA2) != 0 {
                continue;
            }

            let w0_with_hints = w0;
            poly_vec_k_add(&mut w0, &w0_with_hints, &hints);
            let hint_count = poly_vec_k_make_hint(&mut hints, &w0, &w1);
            if hint_count > OMEGA {
                continue;
            }

            pack_sig(signature, &challenge, &z, &hints);
            return Ok(());
        }
    })();

    key.zeroize();
    rho_prime.zeroize();
    zero_poly_vec_l(&mut s1);
    zero_poly_vec_k(&mut s2);
    zero_poly_vec_k(&mut t0);

    result
}

fn crypto_sign(
    message: &[u8],
    secret_key: &[u8; DILITHIUM_SECRET_KEY_SIZE],
    randomized_signing: bool,
) -> Result<Vec<u8>> {
    let mut signed_message = vec![0_u8; DILITHIUM_SIGNATURE_SIZE + message.len()];
    signed_message[DILITHIUM_SIGNATURE_SIZE..].copy_from_slice(message);
    let mut signature = [0_u8; DILITHIUM_SIGNATURE_SIZE];
    crypto_sign_signature(&mut signature, message, secret_key, randomized_signing)?;
    signed_message[..DILITHIUM_SIGNATURE_SIZE].copy_from_slice(&signature);
    Ok(signed_message)
}

fn crypto_sign_verify(
    signature: &[u8; DILITHIUM_SIGNATURE_SIZE],
    message: &[u8],
    public_key: &[u8; DILITHIUM_PUBLIC_KEY_SIZE],
) -> bool {
    let mut buffer = [0_u8; K * POLY_W1_PACKED_BYTES];
    let mut rho = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut challenge = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut challenge_recomputed = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
    let mut mu = [0_u8; CRH_BYTES];
    let mut z = PolyVecL::default();
    let mut matrix = [PolyVecL::default(); K];
    let mut t1 = PolyVecK::default();
    let mut w1 = PolyVecK::default();
    let mut hints = PolyVecK::default();
    let mut challenge_poly = Poly::default();

    unpack_pk(&mut rho, &mut t1, public_key);
    if unpack_sig(&mut challenge, &mut z, &mut hints, signature) {
        return false;
    }
    if poly_vec_l_chk_norm(&z, GAMMA1 - BETA) != 0 {
        return false;
    }

    let mut pk_hash = [0_u8; TR_BYTES];
    shake256(&mut pk_hash, public_key);
    shake256_many(&mut mu, &[&pk_hash, message]);

    poly_challenge(&mut challenge_poly, &challenge);
    poly_vec_matrix_expand(&mut matrix, &rho);

    poly_vec_l_ntt(&mut z);
    poly_vec_matrix_point_wise_montgomery(&mut w1, &matrix, &z);

    poly_ntt(&mut challenge_poly);
    poly_vec_k_shift_l(&mut t1);
    poly_vec_k_ntt(&mut t1);
    let t1_current = t1;
    poly_vec_k_point_wise_poly_montgomery(&mut t1, &challenge_poly, &t1_current);

    let w1_current = w1;
    poly_vec_k_sub(&mut w1, &w1_current, &t1);
    poly_vec_k_reduce(&mut w1);
    poly_vec_k_inv_ntt_to_mont(&mut w1);

    poly_vec_k_cadd_q(&mut w1);
    let hinted_w1 = w1;
    poly_vec_k_use_hint(&mut w1, &hinted_w1, &hints);
    poly_vec_k_pack_w1(&mut buffer, &w1);
    shake256_many(&mut challenge_recomputed, &[&mu, &buffer]);

    constant_time_eq(&challenge, &challenge_recomputed)
}

fn crypto_sign_open(
    signed_message: &[u8],
    public_key: &[u8; DILITHIUM_PUBLIC_KEY_SIZE],
) -> Option<Vec<u8>> {
    if signed_message.len() < DILITHIUM_SIGNATURE_SIZE {
        return None;
    }

    let mut signature = [0_u8; DILITHIUM_SIGNATURE_SIZE];
    signature.copy_from_slice(&signed_message[..DILITHIUM_SIGNATURE_SIZE]);
    let message = &signed_message[DILITHIUM_SIGNATURE_SIZE..];

    if crypto_sign_verify(&signature, message, public_key) { Some(message.to_vec()) } else { None }
}

#[cfg(test)]
mod tests {
    use super::{
        DILITHIUM_CRYPTO_SEED_SIZE, DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SECRET_KEY_SIZE,
        DILITHIUM_SIGNATURE_SIZE, Dilithium, OMEGA, POLY_Z_PACKED_BYTES, dilithium_extract_message,
        dilithium_extract_signature, dilithium_open, sign_dilithium_with_secret_key,
        validate_dilithium_public_key, validate_dilithium_secret_key, verify_dilithium_signature,
    };
    use crate::QrllibError;
    use sha2::Digest;

    const HEX_SEED: &str = "f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb";

    const SEED_BYTES: usize = DILITHIUM_CRYPTO_SEED_SIZE;

    fn known_seed() -> [u8; DILITHIUM_CRYPTO_SEED_SIZE] {
        let mut seed = [0_u8; DILITHIUM_CRYPTO_SEED_SIZE];
        seed.copy_from_slice(&hex::decode(HEX_SEED).expect("seed"));
        seed
    }

    #[test]
    fn dilithium_sizes_and_seed_import_match_go() {
        assert_eq!(DILITHIUM_PUBLIC_KEY_SIZE, 2592);
        assert_eq!(DILITHIUM_SECRET_KEY_SIZE, 4896);
        assert_eq!(DILITHIUM_SIGNATURE_SIZE, 4595);

        let signer = Dilithium::from_seed(known_seed());
        let imported = Dilithium::from_hex_seed(HEX_SEED).expect("from hex");
        assert_eq!(signer.public_key_bytes(), imported.public_key_bytes());
        assert_eq!(signer.secret_key_bytes(), imported.secret_key_bytes());
        assert_eq!(signer.hex_seed(), format!("0x{HEX_SEED}"));
        assert_eq!(
            hex::encode(sha2::Sha256::digest(signer.public_key_bytes())),
            "a51c3f7f2b2c2b5dad6361e4ba94e140df528848fa7310f2421440b0e1fc31e2"
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(signer.secret_key_bytes())),
            "b086066341e3b36c2cfe7124d6cb5767e164054ef655929d411b0410638d37ca"
        );
        assert!(matches!(
            Dilithium::from_hex_seed("0x00"),
            Err(QrllibError::InvalidDilithiumSeedSize(1, DILITHIUM_CRYPTO_SEED_SIZE))
        ));
    }

    #[test]
    fn dilithium_sign_verify_open_and_extract_round_trip() {
        let signer = Dilithium::from_seed(known_seed());
        let message = b"browser wasm dilithium";
        let signature = signer.sign(message).expect("signature");
        assert!(signer.verify(message, &signature));
        assert!(verify_dilithium_signature(message, &signature, &signer.public_key_bytes()));
        assert!(!verify_dilithium_signature(b"tampered", &signature, &signer.public_key_bytes()));

        let sealed = signer.seal(message).expect("sealed");
        assert_eq!(dilithium_extract_message(&sealed).expect("message"), message);
        assert_eq!(dilithium_extract_signature(&sealed).expect("signature"), signature.as_slice());
        assert_eq!(dilithium_open(&sealed, &signer.public_key_bytes()).expect("opened"), message);
        assert_eq!(
            hex::encode(sha2::Sha256::digest(signature)),
            "00a4a27185acccf5feda869e6931f020204c70750fd0800385f0840450444c78"
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&sealed)),
            "055c822bfd5862e6e7cffaff88e5103f229def48a162a3f81c3a50f821e861df"
        );
        assert!(
            dilithium_open(&sealed[..DILITHIUM_SIGNATURE_SIZE - 1], &signer.public_key_bytes())
                .is_none()
        );
        assert!(dilithium_extract_message(&signature[..DILITHIUM_SIGNATURE_SIZE - 1]).is_none());
        assert!(dilithium_extract_signature(&signature[..DILITHIUM_SIGNATURE_SIZE - 1]).is_none());
    }

    #[test]
    fn dilithium_is_deterministic_for_seed_and_message() {
        let seed = known_seed();
        let signer_a = Dilithium::from_seed(seed);
        let signer_b = Dilithium::from_seed(seed);
        let message = [0_u8, 1, 2, 4, 6, 9, 1];

        assert_eq!(signer_a.public_key_bytes(), signer_b.public_key_bytes());
        assert_eq!(signer_a.secret_key_bytes(), signer_b.secret_key_bytes());
        assert_eq!(
            signer_a.sign(&message).expect("signature"),
            signer_b.sign(&message).expect("signature"),
        );
        assert_eq!(
            signer_a.seal(&message).expect("sealed"),
            signer_b.seal(&message).expect("sealed"),
        );
    }

    #[test]
    fn sign_with_secret_key_matches_instance_and_zeroize() {
        let mut signer = Dilithium::from_seed(known_seed());
        let message = b"deterministic legacy dilithium";
        let signature = sign_dilithium_with_secret_key(message, &signer.secret_key_bytes())
            .expect("sign with secret key");
        assert_eq!(signature, signer.sign(message).expect("instance sign"));
        assert!(verify_dilithium_signature(message, &signature, &signer.public_key_bytes()));

        signer.zeroize();
        assert!(signer.seed().iter().all(|byte| *byte == 0));
        assert!(signer.secret_key_bytes().iter().all(|byte| *byte == 0));
        assert!(matches!(
            sign_dilithium_with_secret_key(message, &signer.secret_key_bytes()),
            Err(QrllibError::DilithiumSecretKeyZeroized)
        ));
    }

    #[test]
    fn dilithium_validation_and_error_paths_are_covered() {
        let signer = Dilithium::from_seed(known_seed());
        assert!(validate_dilithium_public_key(&signer.public_key_bytes()).is_ok());
        assert!(validate_dilithium_secret_key(&signer.secret_key_bytes()).is_ok());
        assert!(matches!(
            validate_dilithium_public_key(&[0_u8; 1]),
            Err(QrllibError::InvalidDilithiumPublicKeySize(1, DILITHIUM_PUBLIC_KEY_SIZE))
        ));
        assert!(matches!(
            validate_dilithium_secret_key(&[0_u8; 1]),
            Err(QrllibError::InvalidDilithiumSecretKeySize(1, DILITHIUM_SECRET_KEY_SIZE))
        ));
        assert!(matches!(
            sign_dilithium_with_secret_key(b"", &[0_u8; 1]),
            Err(QrllibError::InvalidDilithiumSecretKeySize(1, DILITHIUM_SECRET_KEY_SIZE))
        ));
        assert!(!verify_dilithium_signature(b"", &[0_u8; 1], &signer.public_key_bytes()));
        assert!(!verify_dilithium_signature(b"", &[0_u8; DILITHIUM_SIGNATURE_SIZE], &[0_u8; 1]));
    }

    #[test]
    fn dilithium_rejects_non_canonical_hint_encodings() {
        let signer = Dilithium::from_seed(known_seed());
        let message = b"test message";
        let valid_signature = signer.sign(message).expect("signature");
        let hint_start = SEED_BYTES + 7 * POLY_Z_PACKED_BYTES;

        let mut non_increasing = valid_signature;
        non_increasing[hint_start + OMEGA] = 2;
        non_increasing[hint_start] = 10;
        non_increasing[hint_start + 1] = 10;
        assert!(!verify_dilithium_signature(message, &non_increasing, &signer.public_key_bytes()));

        let mut decreasing_count = valid_signature;
        decreasing_count[hint_start + OMEGA] = 3;
        decreasing_count[hint_start + OMEGA + 1] = 2;
        decreasing_count[hint_start] = 10;
        decreasing_count[hint_start + 1] = 20;
        decreasing_count[hint_start + 2] = 30;
        assert!(!verify_dilithium_signature(
            message,
            &decreasing_count,
            &signer.public_key_bytes()
        ));

        let mut non_zero_padding = valid_signature;
        for index in 0..8 {
            non_zero_padding[hint_start + OMEGA + index] = 0;
        }
        non_zero_padding[hint_start] = 0xff;
        assert!(!verify_dilithium_signature(
            message,
            &non_zero_padding,
            &signer.public_key_bytes()
        ));
    }
}
