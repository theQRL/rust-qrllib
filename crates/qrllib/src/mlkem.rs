//! ML-KEM-1024 key encapsulation mechanism (FIPS 203).
//!
//! This is a faithful port of `go-qrllib`'s `crypto/internal/mlkem1024`
//! (the IND-CCA-secure construction over K-PKE) and its `crypto/mlkem1024`
//! public wrapper. ML-KEM-1024 targets NIST security category 5.
//!
//! # API
//!
//! - [`DecapsulationKey`] is the private key. Generate one with
//!   [`DecapsulationKey::generate`] (fresh randomness) or restore it
//!   deterministically from a 64-byte `d || z` seed with
//!   [`DecapsulationKey::from_seed`].
//! - [`EncapsulationKey`] is the public key, obtained via
//!   [`DecapsulationKey::encapsulation_key`] or decoded from its bytes with
//!   [`EncapsulationKey::from_bytes`].
//! - [`EncapsulationKey::encapsulate`] produces a `(shared_key, ciphertext)`
//!   pair; [`DecapsulationKey::decapsulate`] recovers the shared key from the
//!   ciphertext.
//!
//! Shared secrets are returned as [`Zeroizing`] byte arrays, and the
//! decapsulation key zeroizes its secret material on drop.
//!
//! # Determinism for test vectors
//!
//! [`EncapsulationKey::encapsulate_deterministic`] takes the 32-byte message
//! explicitly instead of drawing it from the system RNG. It exists only to
//! reproduce ACVP / Wycheproof / cross-verification vectors — production code
//! must use [`EncapsulationKey::encapsulate`], because reusing a message
//! across encapsulations breaks IND-CCA security.

use crate::error::{QrllibError, Result};
use sha3::{
    Digest, Sha3_256, Sha3_512,
    digest::{ExtendableOutput, Update, XofReader},
};
use shake::{Shake128, Shake256};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Public parameters
// ---------------------------------------------------------------------------

/// Size in bytes of the `d || z` seed that deterministically generates an
/// ML-KEM-1024 decapsulation key.
pub const MLKEM1024_SEED_SIZE: usize = 64;

/// Size in bytes of an ML-KEM-1024 shared secret.
pub const MLKEM1024_SHARED_KEY_SIZE: usize = 32;

/// Size in bytes of an ML-KEM-1024 ciphertext.
pub const MLKEM1024_CIPHERTEXT_SIZE: usize = K * ENCODING_SIZE_11 + ENCODING_SIZE_5;

/// Size in bytes of an encoded ML-KEM-1024 encapsulation (public) key.
pub const MLKEM1024_ENCAPSULATION_KEY_SIZE: usize = K * ENCODING_SIZE_12 + 32;

// ---------------------------------------------------------------------------
// Internal parameters
// ---------------------------------------------------------------------------

// ML-KEM global parameters.
const N: usize = 256;
const Q: u16 = 3329;

// ML-KEM-1024 module rank.
const K: usize = 4;

// Byte lengths of ByteEncode_d(f) output (FIPS 203, Algorithm 5).
const ENCODING_SIZE_1: usize = N / 8;
const ENCODING_SIZE_5: usize = N * 5 / 8;
const ENCODING_SIZE_11: usize = N * 11 / 8;
const ENCODING_SIZE_12: usize = N * 12 / 8;

// ML-KEM messages are 32-byte values encoded as ByteEncode_1(m).
const MESSAGE_SIZE: usize = ENCODING_SIZE_1;

const D5: u8 = 5;
const D11: u8 = 11;

const HALF_Q_ROUNDED_UP: u16 = Q.div_ceil(2); // Decompress_1(1) == (q + 1) / 2
const SHAKE128_RATE: usize = 168;

// ---------------------------------------------------------------------------
// Field arithmetic (Z_q, q = 3329)
// ---------------------------------------------------------------------------

/// Reduces a value in `[0, 2q)` to `[0, q)`.
fn field_reduce_once(a: u16) -> u16 {
    let x = a.wrapping_sub(Q);
    // Add q back iff the subtraction went negative (top bit set after wrap).
    x.wrapping_add(Q & (x >> 15).wrapping_neg())
}

fn field_add(a: u16, b: u16) -> u16 {
    field_reduce_once(a.wrapping_add(b))
}

fn field_sub(a: u16, b: u16) -> u16 {
    field_reduce_once(a.wrapping_sub(b).wrapping_add(Q))
}

const BARRETT_MULTIPLIER: u64 = 5039;
const BARRETT_SHIFT: u32 = 24;
const BARRETT_WIDE_MULTIPLIER: u64 = 1_290_167;
const BARRETT_WIDE_SHIFT: u32 = 32;

fn field_reduce(a: u32) -> u16 {
    let quotient = ((a as u64 * BARRETT_MULTIPLIER) >> BARRETT_SHIFT) as u32;
    field_reduce_once(a.wrapping_sub(quotient.wrapping_mul(Q as u32)) as u16)
}

/// Reduces lazy products and accumulators that do not fit the 24-bit Barrett
/// reducer. Current callers stay below about `8*q*q`.
fn field_reduce_wide(a: u32) -> u16 {
    let quotient = ((a as u64 * BARRETT_WIDE_MULTIPLIER) >> BARRETT_WIDE_SHIFT) as u32;
    field_reduce_once(a.wrapping_sub(quotient.wrapping_mul(Q as u32)) as u16)
}

fn field_mul(a: u16, b: u16) -> u16 {
    field_reduce(a as u32 * b as u32)
}

fn field_mul_wide(a: u16, b: u16) -> u16 {
    field_reduce_wide(a as u32 * b as u32)
}

fn field_mul_sub(a: u16, b: u16, c: u16) -> u16 {
    let x = a as u32 * b.wrapping_sub(c).wrapping_add(Q) as u32;
    field_reduce(x)
}

const COMPRESS1_LOWER: u32 = (Q as u32).div_ceil(4); // ceil(q/4) == (q + 3) / 4
const COMPRESS1_UPPER: u32 = (3 * Q as u32) / 4; // floor(3q/4)

fn compress1(x: u16) -> u8 {
    let ux = x as u32;
    let ge_lower = ((ux.wrapping_sub(COMPRESS1_LOWER)) >> 31) ^ 1;
    let le_upper = ((COMPRESS1_UPPER.wrapping_sub(ux)) >> 31) ^ 1;
    (ge_lower & le_upper) as u8
}

fn compress5(x: u16) -> u16 {
    let dividend = (x as u32) << D5;
    let mut quotient = ((dividend as u64 * BARRETT_MULTIPLIER) >> BARRETT_SHIFT) as u32;
    let remainder = dividend.wrapping_sub(quotient.wrapping_mul(Q as u32));
    quotient = quotient.wrapping_add(((Q as u32 / 2).wrapping_sub(remainder) >> 31) & 1);
    quotient = quotient.wrapping_add(((Q as u32 + Q as u32 / 2).wrapping_sub(remainder) >> 31) & 1);
    (quotient & 0x1f) as u16
}

fn compress11(x: u16) -> u16 {
    let dividend = (x as u32) << D11;
    let mut quotient = ((dividend as u64 * BARRETT_MULTIPLIER) >> BARRETT_SHIFT) as u32;
    let remainder = dividend.wrapping_sub(quotient.wrapping_mul(Q as u32));
    quotient = quotient.wrapping_add(((Q as u32 / 2).wrapping_sub(remainder) >> 31) & 1);
    quotient = quotient.wrapping_add(((Q as u32 + Q as u32 / 2).wrapping_sub(remainder) >> 31) & 1);
    (quotient & 0x7ff) as u16
}

fn decompress(y: u16, d: u8) -> u16 {
    let dividend = (y as u32) * (Q as u32);
    let mut quotient = dividend >> d;
    quotient += (dividend >> (d - 1)) & 1;
    quotient as u16
}

// ---------------------------------------------------------------------------
// Ring elements and (de)serialisation
// ---------------------------------------------------------------------------

/// A degree-255 polynomial in `Z_q[X]/(X^256 + 1)`.
type RingElement = [u16; N];

fn new_ring() -> RingElement {
    [0u16; N]
}

fn ring_decode_and_decompress1(dst: &mut RingElement, src: &[u8]) {
    for (i, slot) in dst.iter_mut().enumerate() {
        // Decode one message bit, so the result is either 0 or 1; since q is
        // odd, Decompress_1 maps 1 to (q+1)/2, rounding q/2 up.
        let b = (src[i / 8] >> (i % 8)) & 1;
        *slot = (b as u16) * HALF_Q_ROUNDED_UP;
    }
}

fn ring_decode_and_decompress5(dst: &mut RingElement, src: &[u8]) {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let b0 = src[off] as u16;
        let b1 = src[off + 1] as u16;
        let b2 = src[off + 2] as u16;
        let b3 = src[off + 3] as u16;
        let b4 = src[off + 4] as u16;

        dst[i] = decompress(b0 & 0x1f, D5);
        dst[i + 1] = decompress((b0 >> 5 | b1 << 3) & 0x1f, D5);
        dst[i + 2] = decompress((b1 >> 2) & 0x1f, D5);
        dst[i + 3] = decompress((b1 >> 7 | b2 << 1) & 0x1f, D5);
        dst[i + 4] = decompress((b2 >> 4 | b3 << 4) & 0x1f, D5);
        dst[i + 5] = decompress((b3 >> 1) & 0x1f, D5);
        dst[i + 6] = decompress((b3 >> 6 | b4 << 2) & 0x1f, D5);
        dst[i + 7] = decompress((b4 >> 3) & 0x1f, D5);

        i += 8;
        off += 5;
    }
}

fn ring_decode_and_decompress11(dst: &mut RingElement, src: &[u8]) {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let b0 = src[off] as u32;
        let b1 = src[off + 1] as u32;
        let b2 = src[off + 2] as u32;
        let b3 = src[off + 3] as u32;
        let b4 = src[off + 4] as u32;
        let b5 = src[off + 5] as u32;
        let b6 = src[off + 6] as u32;
        let b7 = src[off + 7] as u32;
        let b8 = src[off + 8] as u32;
        let b9 = src[off + 9] as u32;
        let b10 = src[off + 10] as u32;

        dst[i] = decompress(((b0 | b1 << 8) & 0x7ff) as u16, D11);
        dst[i + 1] = decompress(((b1 >> 3 | b2 << 5) & 0x7ff) as u16, D11);
        dst[i + 2] = decompress(((b2 >> 6 | b3 << 2 | b4 << 10) & 0x7ff) as u16, D11);
        dst[i + 3] = decompress(((b4 >> 1 | b5 << 7) & 0x7ff) as u16, D11);
        dst[i + 4] = decompress(((b5 >> 4 | b6 << 4) & 0x7ff) as u16, D11);
        dst[i + 5] = decompress(((b6 >> 7 | b7 << 1 | b8 << 9) & 0x7ff) as u16, D11);
        dst[i + 6] = decompress(((b8 >> 2 | b9 << 6) & 0x7ff) as u16, D11);
        dst[i + 7] = decompress(((b9 >> 5 | b10 << 3) & 0x7ff) as u16, D11);

        i += 8;
        off += 11;
    }
}

fn ring_compress_and_encode1(dst: &mut [u8], src: &RingElement) {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let c0 = compress1(src[i]);
        let c1 = compress1(src[i + 1]);
        let c2 = compress1(src[i + 2]);
        let c3 = compress1(src[i + 3]);
        let c4 = compress1(src[i + 4]);
        let c5 = compress1(src[i + 5]);
        let c6 = compress1(src[i + 6]);
        let c7 = compress1(src[i + 7]);

        dst[off] = c0 | c1 << 1 | c2 << 2 | c3 << 3 | c4 << 4 | c5 << 5 | c6 << 6 | c7 << 7;

        i += 8;
        off += 1;
    }
}

fn ring_compress_and_encode5(dst: &mut [u8], src: &RingElement) {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let c0 = compress5(src[i]);
        let c1 = compress5(src[i + 1]);
        let c2 = compress5(src[i + 2]);
        let c3 = compress5(src[i + 3]);
        let c4 = compress5(src[i + 4]);
        let c5 = compress5(src[i + 5]);
        let c6 = compress5(src[i + 6]);
        let c7 = compress5(src[i + 7]);

        dst[off] = (c0 | c1 << 5) as u8;
        dst[off + 1] = (c1 >> 3 | c2 << 2 | c3 << 7) as u8;
        dst[off + 2] = (c3 >> 1 | c4 << 4) as u8;
        dst[off + 3] = (c4 >> 4 | c5 << 1 | c6 << 6) as u8;
        dst[off + 4] = (c6 >> 2 | c7 << 3) as u8;

        i += 8;
        off += 5;
    }
}

fn ring_compress_and_encode11(dst: &mut [u8], src: &RingElement) {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let c0 = compress11(src[i]) as u32;
        let c1 = compress11(src[i + 1]) as u32;
        let c2 = compress11(src[i + 2]) as u32;
        let c3 = compress11(src[i + 3]) as u32;
        let c4 = compress11(src[i + 4]) as u32;
        let c5 = compress11(src[i + 5]) as u32;
        let c6 = compress11(src[i + 6]) as u32;
        let c7 = compress11(src[i + 7]) as u32;

        dst[off] = c0 as u8;
        dst[off + 1] = (c0 >> 8 | c1 << 3) as u8;
        dst[off + 2] = (c1 >> 5 | c2 << 6) as u8;
        dst[off + 3] = (c2 >> 2) as u8;
        dst[off + 4] = (c2 >> 10 | c3 << 1) as u8;
        dst[off + 5] = (c3 >> 7 | c4 << 4) as u8;
        dst[off + 6] = (c4 >> 4 | c5 << 7) as u8;
        dst[off + 7] = (c5 >> 1) as u8;
        dst[off + 8] = (c5 >> 9 | c6 << 2) as u8;
        dst[off + 9] = (c6 >> 6 | c7 << 5) as u8;
        dst[off + 10] = (c7 >> 3) as u8;

        i += 8;
        off += 11;
    }
}

fn byte_encode12(dst: &mut [u8], p: &RingElement) {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let x = (p[i] as u32) | (p[i + 1] as u32) << 12;
        dst[off] = x as u8;
        dst[off + 1] = (x >> 8) as u8;
        dst[off + 2] = (x >> 16) as u8;
        i += 2;
        off += 3;
    }
}

fn byte_decode12(dst: &mut RingElement, src: &[u8]) -> Result<()> {
    let mut i = 0usize;
    let mut off = 0usize;
    while i < N {
        let x = (src[off] as u32) | (src[off + 1] as u32) << 8 | (src[off + 2] as u32) << 16;
        let c0 = (x & 0x0fff) as u16;
        let c1 = (x >> 12) as u16;
        if c0 >= Q || c1 >= Q {
            return Err(QrllibError::InvalidMlKemEncoding);
        }
        dst[i] = c0;
        dst[i + 1] = c1;
        i += 2;
        off += 3;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// Samples the NTT-domain matrix entry `A[i,j]` from `SHAKE128(rho || j || i)`.
fn sample_ntt(dst: &mut RingElement, rho: &[u8; 32], j_index: u8, i_index: u8) {
    let mut ctx = Shake128::default();
    ctx.update(rho);
    ctx.update(&[j_index, i_index]);
    let mut reader = ctx.finalize_xof();

    let mut j = 0usize;
    let mut buf = [0u8; SHAKE128_RATE];
    let mut off = buf.len();

    loop {
        if off >= buf.len() {
            reader.read(&mut buf);
            off = 0;
        }

        let x0 = (buf[off] as u16) | (((buf[off + 1] & 0x0f) as u16) << 8);
        let x1 = ((buf[off + 1] >> 4) as u16) | ((buf[off + 2] as u16) << 4);
        off += 3;

        if x0 < Q {
            dst[j] = x0;
            j += 1;
        }
        if j >= N {
            break;
        }
        if x1 < Q {
            dst[j] = x1;
            j += 1;
        }
        if j >= N {
            break;
        }
    }
}

/// Samples a noise polynomial with CBD_2 from `SHAKE256(sigma || counter)`.
fn sample_poly_cbd(dst: &mut RingElement, sigma: &[u8; 32], counter: u8) {
    let mut prf = Shake256::default();
    prf.update(sigma);
    prf.update(&[counter]);
    let mut reader = prf.finalize_xof();
    let mut buf = [0u8; 128];
    reader.read(&mut buf);

    let mut i = 0usize;
    let mut j = 0usize;
    while i < buf.len() {
        let t = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        // Each two-bit field in d is the Hamming weight of one input bit pair;
        // CBD_2 maps adjacent weights to one coefficient as a-b mod q.
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);

        dst[j] = cbd2(d, d >> 2);
        dst[j + 1] = cbd2(d >> 4, d >> 6);
        dst[j + 2] = cbd2(d >> 8, d >> 10);
        dst[j + 3] = cbd2(d >> 12, d >> 14);
        dst[j + 4] = cbd2(d >> 16, d >> 18);
        dst[j + 5] = cbd2(d >> 20, d >> 22);
        dst[j + 6] = cbd2(d >> 24, d >> 26);
        dst[j + 7] = cbd2(d >> 28, d >> 30);

        i += 4;
        j += 8;
    }
}

fn cbd2(a: u32, b: u32) -> u16 {
    field_reduce_once(Q.wrapping_add((a & 0x3) as u16).wrapping_sub((b & 0x3) as u16))
}

// ---------------------------------------------------------------------------
// Number-theoretic transform
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

fn ntt(f: &mut RingElement) {
    let mut i = 1usize;
    let mut length = 128usize;
    while length >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + length {
                // Keep butterfly outputs unreduced between layers. Each layer
                // can grow coefficients by at most q, so across the seven NTT
                // layers they stay below 8q and are canonicalized at the end.
                let t = field_mul_wide(zeta, f[j + length]);
                let a = f[j];
                f[j] = a.wrapping_add(t);
                f[j + length] = a.wrapping_add(Q).wrapping_sub(t);
            }
            start += 2 * length;
        }
        length /= 2;
    }
    for coeff in f.iter_mut() {
        *coeff = field_reduce(*coeff as u32);
    }
}

const INVERSE_NTT_SCALE: u16 = 3303;
// The final inverse NTT layer multiplies lower-half outputs by INVERSE_NTT_SCALE
// directly and folds the upper-half scaling into its zeta.
const INVERSE_NTT_FINAL_ZETA: u16 = 1652; // zetas[1] * INVERSE_NTT_SCALE mod q

fn inverse_ntt(f: &mut RingElement) {
    let mut i = 127usize;
    let mut length = 2usize;
    while length < 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + length {
                let t = f[j];
                f[j] = field_add(t, f[j + length]);
                f[j + length] = field_mul_sub(zeta, f[j + length], t);
            }
            start += 2 * length;
        }
        length *= 2;
    }

    for j in 0..128 {
        let t = f[j];
        f[j] = field_mul(field_add(t, f[j + 128]), INVERSE_NTT_SCALE);
        f[j + 128] = field_mul_sub(INVERSE_NTT_FINAL_ZETA, f[j + 128], t);
    }
}

#[rustfmt::skip]
const GAMMAS: [u16; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279,
    1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
    939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
    1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735,
    2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

/// Fuses the four multiplication terms in an ML-KEM-1024 NTT dot product. The
/// repeated lane blocks are intentionally unrolled so each coefficient pair
/// loads `acc` and `gamma` once, accumulates all four products lazily, and
/// reduces only once per output coefficient.
#[allow(clippy::too_many_arguments)]
fn ntt_mul_add4(
    acc: &mut RingElement,
    a0: &RingElement,
    b0: &RingElement,
    a1: &RingElement,
    b1: &RingElement,
    a2: &RingElement,
    b2: &RingElement,
    a3: &RingElement,
    b3: &RingElement,
) {
    let mut i = 0usize;
    while i < N {
        let gamma = GAMMAS[i / 2] as u32;

        let (a00, a01) = (a0[i], a0[i + 1]);
        let (b00, b01) = (b0[i], b0[i + 1]);
        let mut acc0 = acc[i] as u32;
        acc0 += (a00 as u32) * (b00 as u32) + (field_mul(a01, b01) as u32) * gamma;
        let mut acc1 = acc[i + 1] as u32;
        acc1 += (a00 as u32) * (b01 as u32) + (a01 as u32) * (b00 as u32);

        let (a10, a11) = (a1[i], a1[i + 1]);
        let (b10, b11) = (b1[i], b1[i + 1]);
        acc0 += (a10 as u32) * (b10 as u32) + (field_mul(a11, b11) as u32) * gamma;
        acc1 += (a10 as u32) * (b11 as u32) + (a11 as u32) * (b10 as u32);

        let (a20, a21) = (a2[i], a2[i + 1]);
        let (b20, b21) = (b2[i], b2[i + 1]);
        acc0 += (a20 as u32) * (b20 as u32) + (field_mul(a21, b21) as u32) * gamma;
        acc1 += (a20 as u32) * (b21 as u32) + (a21 as u32) * (b20 as u32);

        let (a30, a31) = (a3[i], a3[i + 1]);
        let (b30, b31) = (b3[i], b3[i + 1]);
        acc0 += (a30 as u32) * (b30 as u32) + (field_mul(a31, b31) as u32) * gamma;
        acc1 += (a30 as u32) * (b31 as u32) + (a31 as u32) * (b30 as u32);

        acc[i] = field_reduce_wide(acc0);
        acc[i + 1] = field_reduce_wide(acc1);
        i += 2;
    }
}

fn poly_add_assign(a: &mut RingElement, b: &RingElement) {
    for i in 0..N {
        a[i] = field_add(a[i], b[i]);
    }
}

fn poly_sub_assign(a: &mut RingElement, b: &RingElement) {
    for i in 0..N {
        a[i] = field_sub(a[i], b[i]);
    }
}

// ---------------------------------------------------------------------------
// Hash helpers (FIPS 202)
// ---------------------------------------------------------------------------

fn sha3_512(input: &[u8]) -> [u8; 64] {
    let out = Sha3_512::digest(input);
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

fn sha3_256(input: &[u8]) -> [u8; 32] {
    let out = Sha3_256::digest(input);
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn shake256(inputs: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for input in inputs {
        h.update(input);
    }
    let mut reader = h.finalize_xof();
    reader.read(out);
}

// ---------------------------------------------------------------------------
// Constant-time helpers
// ---------------------------------------------------------------------------

/// Returns `0xFF` if the slices are equal, `0x00` otherwise, in time
/// independent of where the first difference (if any) occurs.
fn ct_eq_mask(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // diff != 0  ->  bit 31 set  ->  nonzero == 1
    let nonzero = (diff as u32 | (diff as u32).wrapping_neg()) >> 31;
    ((nonzero ^ 1) as u8).wrapping_neg()
}

/// `dst = src` where `mask == 0xFF`, leaves `dst` unchanged where `mask ==
/// 0x00`. Data-independent.
fn ct_select(mask: u8, dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct EncryptionKey {
    t: [RingElement; K],     // public key vector in NTT domain
    a: [RingElement; K * K], // public matrix A in NTT domain
    rho: [u8; 32],           // matrix seed
    encoded: [u8; MLKEM1024_ENCAPSULATION_KEY_SIZE], // encoded t || rho
}

impl EncryptionKey {
    fn zeroed() -> Self {
        Self {
            t: [new_ring(); K],
            a: [new_ring(); K * K],
            rho: [0u8; 32],
            encoded: [0u8; MLKEM1024_ENCAPSULATION_KEY_SIZE],
        }
    }
}

#[derive(Clone)]
struct DecryptionKey {
    s: [RingElement; K], // secret key vector in NTT domain
}

/// An ML-KEM-1024 decapsulation (private) key.
///
/// Holds secret material — the `d`/`z` seeds and the secret vector `s` — which
/// is zeroized on drop. Deliberately not [`Clone`]: copy the seed via
/// [`DecapsulationKey::bytes`] and re-derive instead.
pub struct DecapsulationKey {
    d: [u8; 32], // decapsulation key seed
    z: [u8; 32], // implicit-rejection seed
    h: [u8; 32], // H(ek)
    encryption_key: EncryptionKey,
    decryption_key: DecryptionKey,
}

/// An ML-KEM-1024 encapsulation (public) key.
#[derive(Clone)]
pub struct EncapsulationKey {
    h: [u8; 32], // H(ek)
    encryption_key: EncryptionKey,
}

impl DecapsulationKey {
    /// Generates a fresh decapsulation key from system randomness.
    pub fn generate() -> Result<Self> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        getrandom::getrandom(&mut d)?;
        getrandom::getrandom(&mut z)?;
        let key = Self::from_d_z(&d, &z);
        d.zeroize();
        z.zeroize();
        Ok(key)
    }

    /// Deterministically derives a decapsulation key from a
    /// [`MLKEM1024_SEED_SIZE`]-byte seed in `d || z` form.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != MLKEM1024_SEED_SIZE {
            return Err(QrllibError::InvalidMlKemSeedSize(seed.len(), MLKEM1024_SEED_SIZE));
        }
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let key = Self::from_d_z(&d, &z);
        d.zeroize();
        z.zeroize();
        Ok(key)
    }

    fn from_d_z(d: &[u8; 32], z: &[u8; 32]) -> Self {
        let mut dk = DecapsulationKey {
            d: *d,
            z: *z,
            h: [0u8; 32],
            encryption_key: EncryptionKey::zeroed(),
            decryption_key: DecryptionKey { s: [new_ring(); K] },
        };
        pke_key_gen(&mut dk, d);
        dk.h = sha3_256(&dk.encryption_key.encoded);
        dk
    }

    /// Recovers the shared secret from an ML-KEM-1024 ciphertext. Implements
    /// the Fujisaki-Okamoto re-encryption check with constant-time implicit
    /// rejection: a malformed ciphertext yields a pseudo-random key derived
    /// from `z`, never an error.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; MLKEM1024_SHARED_KEY_SIZE]>> {
        if ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE {
            return Err(QrllibError::InvalidMlKemCiphertextSize(
                ciphertext.len(),
                MLKEM1024_CIPHERTEXT_SIZE,
            ));
        }
        let mut ct = [0u8; MLKEM1024_CIPHERTEXT_SIZE];
        ct.copy_from_slice(ciphertext);
        Ok(decapsulate(self, &ct))
    }

    /// Returns the corresponding encapsulation (public) key.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey { h: self.h, encryption_key: self.encryption_key.clone() }
    }

    /// Returns the decapsulation key seed in `d || z` form.
    pub fn bytes(&self) -> Zeroizing<[u8; MLKEM1024_SEED_SIZE]> {
        let mut b = [0u8; MLKEM1024_SEED_SIZE];
        b[..32].copy_from_slice(&self.d);
        b[32..].copy_from_slice(&self.z);
        Zeroizing::new(b)
    }

    /// Overwrites the secret material — the `d`/`z` seeds and secret vector
    /// `s` — with zeros. Best-effort under Rust's memory model. Non-secret
    /// fields (the encapsulation key, matrix seed, and `H(ek)`) are left
    /// intact.
    pub fn zeroize(&mut self) {
        self.d.zeroize();
        self.z.zeroize();
        for poly in &mut self.decryption_key.s {
            poly.zeroize();
        }
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EncapsulationKey {
    /// Constructs an encapsulation key from its
    /// [`MLKEM1024_ENCAPSULATION_KEY_SIZE`]-byte encoded form. Rejects
    /// non-canonical encodings (any coefficient `>= q`).
    pub fn from_bytes(ek_bytes: &[u8]) -> Result<Self> {
        if ek_bytes.len() != MLKEM1024_ENCAPSULATION_KEY_SIZE {
            return Err(QrllibError::InvalidMlKemEncapsulationKeySize(
                ek_bytes.len(),
                MLKEM1024_ENCAPSULATION_KEY_SIZE,
            ));
        }

        let mut ek =
            EncapsulationKey { h: sha3_256(ek_bytes), encryption_key: EncryptionKey::zeroed() };
        ek.encryption_key.encoded.copy_from_slice(ek_bytes);

        let mut offset = 0usize;
        for i in 0..K {
            byte_decode12(
                &mut ek.encryption_key.t[i],
                &ek_bytes[offset..offset + ENCODING_SIZE_12],
            )?;
            offset += ENCODING_SIZE_12;
        }
        ek.encryption_key.rho.copy_from_slice(&ek_bytes[offset..offset + 32]);

        let rho = ek.encryption_key.rho;
        for i in 0..K {
            for j in 0..K {
                sample_ntt(&mut ek.encryption_key.a[i * K + j], &rho, j as u8, i as u8);
            }
        }

        Ok(ek)
    }

    /// Produces a fresh `(shared_key, ciphertext)` pair using system
    /// randomness for the encapsulated message.
    pub fn encapsulate(
        &self,
    ) -> Result<(Zeroizing<[u8; MLKEM1024_SHARED_KEY_SIZE]>, [u8; MLKEM1024_CIPHERTEXT_SIZE])> {
        let mut m = [0u8; MESSAGE_SIZE];
        getrandom::getrandom(&mut m)?;
        let (shared_key, ciphertext) = encapsulate_to(&self.encryption_key, &self.h, &m);
        m.zeroize();
        Ok((shared_key, ciphertext))
    }

    /// Derandomized counterpart to [`EncapsulationKey::encapsulate`] that takes
    /// the 32-byte message `m` explicitly.
    ///
    /// **Test-only.** Reusing `m` across encapsulations breaks IND-CCA
    /// security; this exists solely to reproduce ACVP / Wycheproof /
    /// cross-verification vectors. Production code must call
    /// [`EncapsulationKey::encapsulate`].
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; MESSAGE_SIZE],
    ) -> (Zeroizing<[u8; MLKEM1024_SHARED_KEY_SIZE]>, [u8; MLKEM1024_CIPHERTEXT_SIZE]) {
        encapsulate_to(&self.encryption_key, &self.h, m)
    }

    /// Returns the encoded form of the encapsulation key.
    pub fn bytes(&self) -> [u8; MLKEM1024_ENCAPSULATION_KEY_SIZE] {
        self.encryption_key.encoded
    }
}

// ---------------------------------------------------------------------------
// K-PKE (FIPS 203, Section 5): the IND-CPA-secure PKE that ML-KEM wraps with
// the FO transform.
// ---------------------------------------------------------------------------

fn pke_key_gen(dk: &mut DecapsulationKey, d: &[u8; 32]) {
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = K as u8;
    let mut g = sha3_512(&g_input);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    dk.encryption_key.rho = rho;
    dk.encryption_key.encoded[K * ENCODING_SIZE_12..].copy_from_slice(&rho);

    for i in 0..K {
        for j in 0..K {
            sample_ntt(&mut dk.encryption_key.a[i * K + j], &rho, j as u8, i as u8);
        }
    }

    let mut counter = 0u8;
    for i in 0..K {
        sample_poly_cbd(&mut dk.decryption_key.s[i], &sigma, counter);
        ntt(&mut dk.decryption_key.s[i]);
        counter += 1;
    }

    for i in 0..K {
        let mut acc = new_ring();
        ntt_mul_add4(
            &mut acc,
            &dk.encryption_key.a[i * K],
            &dk.decryption_key.s[0],
            &dk.encryption_key.a[i * K + 1],
            &dk.decryption_key.s[1],
            &dk.encryption_key.a[i * K + 2],
            &dk.decryption_key.s[2],
            &dk.encryption_key.a[i * K + 3],
            &dk.decryption_key.s[3],
        );

        let mut e = new_ring();
        sample_poly_cbd(&mut e, &sigma, counter);
        ntt(&mut e);
        counter += 1;
        poly_add_assign(&mut acc, &e);
        e.zeroize(); // noise secret; no longer needed

        dk.encryption_key.t[i] = acc;
        byte_encode12(
            &mut dk.encryption_key.encoded[i * ENCODING_SIZE_12..(i + 1) * ENCODING_SIZE_12],
            &dk.encryption_key.t[i],
        );
    }

    // Wipe key-generation secrets: g_input holds the seed d, g/sigma hold the
    // CBD sampling seed.
    g_input.zeroize();
    g.zeroize();
    sigma.zeroize();
    rho.zeroize();
}

fn pke_encrypt(
    dst: &mut [u8; MLKEM1024_CIPHERTEXT_SIZE],
    ek: &EncryptionKey,
    m: &[u8; MESSAGE_SIZE],
    r: &[u8; 32],
) {
    let mut counter = 0u8;
    let mut y = [new_ring(); K];
    for poly in &mut y {
        sample_poly_cbd(poly, r, counter);
        ntt(poly);
        counter += 1;
    }

    let mut off = 0usize;
    for i in 0..K {
        let mut acc = new_ring();
        // ek.a is stored row-major as A[row*K + column]. K-PKE.Encrypt needs
        // A^T * y, so this walks one column of A for each output polynomial.
        ntt_mul_add4(
            &mut acc,
            &ek.a[i],
            &y[0],
            &ek.a[K + i],
            &y[1],
            &ek.a[2 * K + i],
            &y[2],
            &ek.a[3 * K + i],
            &y[3],
        );
        inverse_ntt(&mut acc);

        let mut e1 = new_ring();
        sample_poly_cbd(&mut e1, r, counter);
        counter += 1;
        poly_add_assign(&mut acc, &e1);
        e1.zeroize(); // noise secret; acc (= u_i) is public ciphertext

        ring_compress_and_encode11(&mut dst[off..off + ENCODING_SIZE_11], &acc);
        off += ENCODING_SIZE_11;
    }

    let mut e2 = new_ring();
    sample_poly_cbd(&mut e2, r, counter);

    let mut mu = new_ring();
    ring_decode_and_decompress1(&mut mu, m);

    let mut v = new_ring();
    ntt_mul_add4(&mut v, &ek.t[0], &y[0], &ek.t[1], &y[1], &ek.t[2], &y[2], &ek.t[3], &y[3]);
    inverse_ntt(&mut v);
    poly_add_assign(&mut v, &e2);
    poly_add_assign(&mut v, &mu);

    ring_compress_and_encode5(&mut dst[off..off + ENCODING_SIZE_5], &v);

    // Wipe encryption secrets: y is the encryption randomness vector, e2/mu
    // derive from the message randomness, and full-precision v carries mu
    // before compression rounding. The u_i accumulators are not wiped — they
    // are the public ciphertext content.
    for poly in &mut y {
        poly.zeroize();
    }
    e2.zeroize();
    mu.zeroize();
    v.zeroize();
}

fn pke_decrypt(
    dst: &mut [u8; MESSAGE_SIZE],
    dk: &DecapsulationKey,
    c: &[u8; MLKEM1024_CIPHERTEXT_SIZE],
) {
    let mut u = [new_ring(); K];
    let mut off = 0usize;
    for poly in &mut u {
        ring_decode_and_decompress11(poly, &c[off..off + ENCODING_SIZE_11]);
        off += ENCODING_SIZE_11;
        ntt(poly);
    }

    let mut v = new_ring();
    ring_decode_and_decompress5(&mut v, &c[off..off + ENCODING_SIZE_5]);

    let s = &dk.decryption_key.s;
    let mut acc = new_ring();
    ntt_mul_add4(&mut acc, &s[0], &u[0], &s[1], &u[1], &s[2], &u[2], &s[3], &u[3]);
    inverse_ntt(&mut acc);

    poly_sub_assign(&mut v, &acc);
    ring_compress_and_encode1(dst, &v);

    // Wipe decryption secrets: acc is s^T·u (secret-key-dependent) and v holds
    // the noisy plaintext polynomial after the subtraction. The decoded u is
    // public ciphertext content and is left as is. dst (the decrypted message)
    // is wiped by decapsulate after the FO re-encryption check.
    acc.zeroize();
    v.zeroize();
}

// ---------------------------------------------------------------------------
// ML-KEM FO transform
// ---------------------------------------------------------------------------

fn encapsulate_to(
    ek: &EncryptionKey,
    ek_h: &[u8; 32],
    m: &[u8; MESSAGE_SIZE],
) -> (Zeroizing<[u8; MLKEM1024_SHARED_KEY_SIZE]>, [u8; MLKEM1024_CIPHERTEXT_SIZE]) {
    let mut g_input = [0u8; MESSAGE_SIZE + 32];
    g_input[..MESSAGE_SIZE].copy_from_slice(m);
    g_input[MESSAGE_SIZE..].copy_from_slice(ek_h);
    let mut g = sha3_512(&g_input);

    let mut shared_key = [0u8; MLKEM1024_SHARED_KEY_SIZE];
    shared_key.copy_from_slice(&g[..MLKEM1024_SHARED_KEY_SIZE]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[MLKEM1024_SHARED_KEY_SIZE..]);

    let mut ciphertext = [0u8; MLKEM1024_CIPHERTEXT_SIZE];
    pke_encrypt(&mut ciphertext, ek, m, &r);

    // Wipe transient secret material derived from the message randomness. m is
    // owned by the caller and left intact.
    g_input.zeroize();
    g.zeroize();
    r.zeroize();

    (Zeroizing::new(shared_key), ciphertext)
}

fn decapsulate(
    dk: &DecapsulationKey,
    ct: &[u8; MLKEM1024_CIPHERTEXT_SIZE],
) -> Zeroizing<[u8; MLKEM1024_SHARED_KEY_SIZE]> {
    let mut m = [0u8; MESSAGE_SIZE];
    pke_decrypt(&mut m, dk, ct);

    let mut g_input = [0u8; MESSAGE_SIZE + 32];
    g_input[..MESSAGE_SIZE].copy_from_slice(&m);
    g_input[MESSAGE_SIZE..].copy_from_slice(&dk.h);
    let mut g = sha3_512(&g_input);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[MLKEM1024_SHARED_KEY_SIZE..]);

    // Implicit-rejection key J(z || ct): the default output for a ciphertext
    // that fails the re-encryption check.
    let mut k_out = [0u8; MLKEM1024_SHARED_KEY_SIZE];
    shake256(&[&dk.z, ct.as_slice()], &mut k_out);

    let mut c = [0u8; MLKEM1024_CIPHERTEXT_SIZE];
    pke_encrypt(&mut c, &dk.encryption_key, &m, &r);

    // If the re-encryption matches, replace the implicit-rejection key with the
    // real shared key G(m || H(ek))[:32]. Constant-time; data-independent wipes
    // below add no timing side channel.
    let matches = ct_eq_mask(ct.as_slice(), &c);
    ct_select(matches, &mut k_out, &g[..MLKEM1024_SHARED_KEY_SIZE]);

    m.zeroize();
    g_input.zeroize();
    g.zeroize();
    r.zeroize();

    Zeroizing::new(k_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; MLKEM1024_SEED_SIZE] {
        [byte; MLKEM1024_SEED_SIZE]
    }

    #[test]
    fn sizes_match_fips_203_ml_kem_1024() {
        assert_eq!(MLKEM1024_SEED_SIZE, 64);
        assert_eq!(MLKEM1024_SHARED_KEY_SIZE, 32);
        assert_eq!(MLKEM1024_CIPHERTEXT_SIZE, 1568);
        assert_eq!(MLKEM1024_ENCAPSULATION_KEY_SIZE, 1568);
    }

    #[test]
    fn encapsulate_then_decapsulate_recovers_shared_secret() {
        let dk = DecapsulationKey::from_seed(&seed(0x42)).expect("decap key");
        let ek = dk.encapsulation_key();
        let (shared_a, ciphertext) = ek.encapsulate().expect("encapsulate");
        let shared_b = dk.decapsulate(&ciphertext).expect("decapsulate");
        assert_eq!(*shared_a, *shared_b);
        assert_eq!(ciphertext.len(), MLKEM1024_CIPHERTEXT_SIZE);
    }

    #[test]
    fn encapsulation_key_round_trips_through_bytes() {
        let dk = DecapsulationKey::from_seed(&seed(7)).expect("decap key");
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.bytes();
        assert_eq!(ek_bytes.len(), MLKEM1024_ENCAPSULATION_KEY_SIZE);

        let restored = EncapsulationKey::from_bytes(&ek_bytes).expect("restore ek");
        let (shared, ciphertext) = restored.encapsulate().expect("encapsulate");
        assert_eq!(*dk.decapsulate(&ciphertext).expect("decapsulate"), *shared);
    }

    #[test]
    fn from_seed_is_deterministic_and_round_trips() {
        let dk1 = DecapsulationKey::from_seed(&seed(0x11)).expect("decap key");
        let dk2 = DecapsulationKey::from_seed(&seed(0x11)).expect("decap key");
        assert_eq!(dk1.encapsulation_key().bytes(), dk2.encapsulation_key().bytes());
        assert_eq!(*dk1.bytes(), *dk2.bytes());

        // A different seed yields a different public key.
        let dk3 = DecapsulationKey::from_seed(&seed(0x12)).expect("decap key");
        assert_ne!(dk1.encapsulation_key().bytes(), dk3.encapsulation_key().bytes());
    }

    #[test]
    fn deterministic_encapsulation_is_reproducible() {
        let dk = DecapsulationKey::from_seed(&seed(0x99)).expect("decap key");
        let ek = dk.encapsulation_key();
        let m = [0x5a_u8; MESSAGE_SIZE];
        let (shared_a, ct_a) = ek.encapsulate_deterministic(&m);
        let (shared_b, ct_b) = ek.encapsulate_deterministic(&m);
        assert_eq!(*shared_a, *shared_b);
        assert_eq!(ct_a, ct_b);
        assert_eq!(*dk.decapsulate(&ct_a).expect("decapsulate"), *shared_a);
    }

    #[test]
    fn decapsulate_implicitly_rejects_malformed_ciphertext() {
        let dk = DecapsulationKey::from_seed(&seed(0x33)).expect("decap key");
        let ek = dk.encapsulation_key();
        let (_shared, mut ciphertext) = ek.encapsulate().expect("encapsulate");

        // Flip a byte: decapsulation must return a pseudo-random key (derived
        // from z), not an error, and not the real shared secret.
        ciphertext[0] ^= 0xff;
        let rejected = dk.decapsulate(&ciphertext).expect("implicit rejection still succeeds");
        let valid = dk.decapsulate(&ek.encapsulate().expect("encapsulate").1).expect("decapsulate");
        assert_ne!(*rejected, *valid);
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        assert!(matches!(
            DecapsulationKey::from_seed(&[0u8; 32]),
            Err(QrllibError::InvalidMlKemSeedSize(32, 64))
        ));
        let dk = DecapsulationKey::from_seed(&seed(1)).expect("decap key");
        assert!(matches!(
            dk.decapsulate(&[0u8; 10]),
            Err(QrllibError::InvalidMlKemCiphertextSize(10, 1568))
        ));
        assert!(matches!(
            EncapsulationKey::from_bytes(&[0u8; 100]),
            Err(QrllibError::InvalidMlKemEncapsulationKeySize(100, 1568))
        ));
    }

    #[test]
    fn from_bytes_rejects_non_canonical_encoding() {
        let dk = DecapsulationKey::from_seed(&seed(0x55)).expect("decap key");
        let mut ek_bytes = dk.encapsulation_key().bytes();
        // Force the first encoded coefficient (12 bits spanning bytes[0..2]) to
        // 0xfff = 4095, which is >= q, so byte_decode12 must reject the key
        // rather than accept a non-canonical encoding.
        ek_bytes[0] = 0xff;
        ek_bytes[1] |= 0x0f;
        assert!(matches!(
            EncapsulationKey::from_bytes(&ek_bytes),
            Err(QrllibError::InvalidMlKemEncoding)
        ));
    }

    #[test]
    fn decapsulation_key_zeroize_clears_secret_material() {
        let mut dk = DecapsulationKey::from_seed(&seed(0x77)).expect("decap key");
        dk.zeroize();
        assert!(dk.d.iter().all(|b| *b == 0));
        assert!(dk.z.iter().all(|b| *b == 0));
        assert!(dk.decryption_key.s.iter().all(|poly| poly.iter().all(|c| *c == 0)));
    }
}

/// NIST ACVP known-answer tests for ML-KEM-1024 (FIPS 203), ported from
/// go-qrllib's `crypto/internal/mlkem1024/acvp_test.go`.
///
/// Lives in-module because the ACVP `decapsulation` and `decapsulationKeyCheck`
/// functions operate on the **expanded** decapsulation-key encoding
/// (`dkPKE || ek || H(ek) || z`, 3168 bytes), which requires private-field
/// access that the public API deliberately does not expose (parity with
/// go-qrllib, which keeps the seed `d || z` as the canonical key bytes).
///
/// Vectors are **not** vendored. Point `MLKEM_ACVP_VECTORS_DIR` at a directory
/// containing the decompressed NIST ACVP suites
/// `ML-KEM-keyGen-FIPS203/{prompt,expectedResults}.json` and
/// `ML-KEM-encapDecap-FIPS203/{prompt,expectedResults}.json`. When the variable
/// is unset the tests log a skip and pass, so day-to-day `cargo test` does not
/// require the vectors. See `.github/acvp/README.md`.
#[cfg(test)]
mod acvp {
    use super::*;
    use serde::Deserialize;
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    #[derive(Deserialize)]
    struct PromptFile {
        #[serde(rename = "testGroups")]
        test_groups: Vec<PromptGroup>,
    }

    #[derive(Deserialize)]
    struct PromptGroup {
        #[serde(rename = "tgId")]
        tg_id: u32,
        #[serde(rename = "parameterSet")]
        parameter_set: String,
        #[serde(default)]
        function: String,
        tests: Vec<PromptTest>,
    }

    #[derive(Deserialize)]
    struct PromptTest {
        #[serde(rename = "tcId")]
        tc_id: u32,
        #[serde(default)]
        d: String,
        #[serde(default)]
        z: String,
        #[serde(default)]
        ek: String,
        #[serde(default)]
        dk: String,
        #[serde(default)]
        m: String,
        #[serde(default)]
        c: String,
    }

    #[derive(Deserialize)]
    struct ExpectedFile {
        #[serde(rename = "testGroups")]
        test_groups: Vec<ExpectedGroup>,
    }

    #[derive(Deserialize)]
    struct ExpectedGroup {
        #[serde(rename = "tgId")]
        tg_id: u32,
        tests: Vec<ExpectedTest>,
    }

    #[derive(Deserialize)]
    struct ExpectedTest {
        #[serde(rename = "tcId")]
        tc_id: u32,
        #[serde(default)]
        ek: String,
        #[serde(default)]
        dk: String,
        #[serde(default)]
        c: String,
        #[serde(default)]
        k: String,
        #[serde(rename = "testPassed", default)]
        test_passed: bool,
    }

    fn vectors_dir() -> Option<PathBuf> {
        env::var_os("MLKEM_ACVP_VECTORS_DIR").map(PathBuf::from)
    }

    fn load<T: serde::de::DeserializeOwned>(dir: &Path, suite: &str, name: &str) -> T {
        let path = dir.join(suite).join(name);
        let data =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
    }

    fn decode(value: &str) -> Vec<u8> {
        hex::decode(value).expect("ACVP hex")
    }

    fn expected_test(expected: &ExpectedFile, tg_id: u32, tc_id: u32) -> &ExpectedTest {
        expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == tg_id)
            .unwrap_or_else(|| panic!("missing expected group {tg_id}"))
            .tests
            .iter()
            .find(|t| t.tc_id == tc_id)
            .unwrap_or_else(|| panic!("missing expected test {tc_id} in group {tg_id}"))
    }

    /// Serialise a decapsulation key into the FIPS 203 / ACVP expanded form
    /// `ByteEncode12(s) || ek || H(ek) || z`.
    fn to_expanded(dk: &DecapsulationKey) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(K * ENCODING_SIZE_12 + MLKEM1024_ENCAPSULATION_KEY_SIZE + 64);
        let mut encoded = [0u8; ENCODING_SIZE_12];
        for poly in &dk.decryption_key.s {
            byte_encode12(&mut encoded, poly);
            out.extend_from_slice(&encoded);
        }
        out.extend_from_slice(&dk.encryption_key.encoded);
        out.extend_from_slice(&dk.h);
        out.extend_from_slice(&dk.z);
        out
    }

    /// Reconstruct a decapsulation key from the ACVP expanded form, validating
    /// the secret vector, embedded encapsulation key, and `H(ek)` consistency —
    /// the predicate the `decapsulationKeyCheck` function asserts.
    fn from_expanded(b: &[u8]) -> Result<DecapsulationKey> {
        const EXPANDED: usize = K * ENCODING_SIZE_12 + MLKEM1024_ENCAPSULATION_KEY_SIZE + 64;
        if b.len() != EXPANDED {
            return Err(QrllibError::InvalidMlKemEncoding);
        }
        let mut s = [new_ring(); K];
        let mut off = 0usize;
        for poly in &mut s {
            byte_decode12(poly, &b[off..off + ENCODING_SIZE_12])?;
            off += ENCODING_SIZE_12;
        }
        let ek = EncapsulationKey::from_bytes(&b[off..off + MLKEM1024_ENCAPSULATION_KEY_SIZE])?;
        off += MLKEM1024_ENCAPSULATION_KEY_SIZE;
        if ek.h[..] != b[off..off + 32] {
            return Err(QrllibError::InvalidMlKemEncoding);
        }
        off += 32;
        let mut z = [0u8; 32];
        z.copy_from_slice(&b[off..off + 32]);
        // `d` is unused by decapsulation (which consumes s, h, z, and the
        // encryption key), so a zero placeholder is sufficient here.
        Ok(DecapsulationKey {
            d: [0u8; 32],
            z,
            h: ek.h,
            encryption_key: ek.encryption_key,
            decryption_key: DecryptionKey { s },
        })
    }

    #[test]
    fn acvp_keygen_matches_nist_vectors() {
        let Some(dir) = vectors_dir() else {
            eprintln!("MLKEM_ACVP_VECTORS_DIR not set; skipping ML-KEM ACVP keyGen test");
            return;
        };
        let suite = "ML-KEM-keyGen-FIPS203";
        let prompt: PromptFile = load(&dir, suite, "prompt.json");
        let expected: ExpectedFile = load(&dir, suite, "expectedResults.json");

        let mut tested = 0u32;
        for group in &prompt.test_groups {
            if group.parameter_set != "ML-KEM-1024" {
                continue;
            }
            for test in &group.tests {
                tested += 1;
                let want = expected_test(&expected, group.tg_id, test.tc_id);
                let mut seed = [0u8; MLKEM1024_SEED_SIZE];
                seed[..32].copy_from_slice(&decode(&test.d));
                seed[32..].copy_from_slice(&decode(&test.z));
                let dk = DecapsulationKey::from_seed(&seed).expect("decapsulation key");
                assert_eq!(
                    dk.encapsulation_key().bytes().as_slice(),
                    decode(&want.ek).as_slice(),
                    "tc{}: encapsulation key mismatch",
                    test.tc_id
                );
                assert_eq!(
                    to_expanded(&dk),
                    decode(&want.dk),
                    "tc{}: expanded decapsulation key mismatch",
                    test.tc_id
                );
            }
        }
        assert!(tested > 0, "no ML-KEM-1024 ACVP keyGen test cases");
        eprintln!("ACVP ML-KEM-1024 keyGen: {tested} cases passed");
    }

    #[test]
    fn acvp_encap_decap_matches_nist_vectors() {
        let Some(dir) = vectors_dir() else {
            eprintln!("MLKEM_ACVP_VECTORS_DIR not set; skipping ML-KEM ACVP encapDecap test");
            return;
        };
        let suite = "ML-KEM-encapDecap-FIPS203";
        let prompt: PromptFile = load(&dir, suite, "prompt.json");
        let expected: ExpectedFile = load(&dir, suite, "expectedResults.json");

        let (mut encap, mut decap, mut decap_check, mut encap_check) = (0u32, 0u32, 0u32, 0u32);
        for group in &prompt.test_groups {
            if group.parameter_set != "ML-KEM-1024" {
                continue;
            }
            for test in &group.tests {
                let want = expected_test(&expected, group.tg_id, test.tc_id);
                match group.function.as_str() {
                    "encapsulation" => {
                        let ek = EncapsulationKey::from_bytes(&decode(&test.ek))
                            .expect("encapsulation key");
                        let m: [u8; 32] = decode(&test.m).try_into().expect("32-byte m");
                        let (shared, ciphertext) = ek.encapsulate_deterministic(&m);
                        assert_eq!(ciphertext, decode(&want.c).as_slice(), "tc{}: ct", test.tc_id);
                        assert_eq!(*shared, decode(&want.k).as_slice(), "tc{}: K", test.tc_id);
                        encap += 1;
                    }
                    "decapsulation" => {
                        let dk = from_expanded(&decode(&test.dk)).expect("decapsulation key");
                        let shared = dk.decapsulate(&decode(&test.c)).expect("decapsulate");
                        assert_eq!(*shared, decode(&want.k).as_slice(), "tc{}: K", test.tc_id);
                        decap += 1;
                    }
                    "decapsulationKeyCheck" => {
                        let ok = from_expanded(&decode(&test.dk)).is_ok();
                        assert_eq!(ok, want.test_passed, "tc{}: dk check", test.tc_id);
                        decap_check += 1;
                    }
                    "encapsulationKeyCheck" => {
                        let ok = EncapsulationKey::from_bytes(&decode(&test.ek)).is_ok();
                        assert_eq!(ok, want.test_passed, "tc{}: ek check", test.tc_id);
                        encap_check += 1;
                    }
                    other => panic!("unexpected ACVP function {other:?}"),
                }
            }
        }
        assert!(
            encap > 0 && decap > 0 && decap_check > 0 && encap_check > 0,
            "missing an ML-KEM-1024 encapDecap function (encap={encap} decap={decap} \
             decapCheck={decap_check} encapCheck={encap_check})"
        );
        eprintln!(
            "ACVP ML-KEM-1024 encapDecap: encap={encap} decap={decap} \
             decapKeyCheck={decap_check} encapKeyCheck={encap_check} passed"
        );
    }
}
