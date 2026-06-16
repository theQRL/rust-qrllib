use crate::{
    error::{QrllibError, Result},
    wallet_type::WalletType,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;
use zeroize::{Zeroize, Zeroizing};

pub const SPHINCS_PLUS_256S_N: usize = 32;
const SPX_FULL_HEIGHT: u32 = 64;
const SPX_D: u32 = 8;
const SPX_FORS_HEIGHT: usize = 14;
const SPX_FORS_TREES: usize = 22;
const SPX_WOTS_W: usize = 16;
const SPX_ADDR_BYTES: usize = 32;
const SPX_WOTS_LOGW: usize = 4;
const SPX_WOTS_LEN1: usize = 8 * SPHINCS_PLUS_256S_N / SPX_WOTS_LOGW;
const SPX_WOTS_LEN2: usize = 3;
const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;
const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPHINCS_PLUS_256S_N;
const SPX_TREE_HEIGHT: u32 = SPX_FULL_HEIGHT / SPX_D;
const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES).div_ceil(8);
const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPHINCS_PLUS_256S_N;

pub const SPHINCS_PLUS_256S_SIGNATURE_SIZE: usize = SPHINCS_PLUS_256S_N
    + SPX_FORS_BYTES
    + (SPX_D as usize) * SPX_WOTS_BYTES
    + (SPX_FULL_HEIGHT as usize) * SPHINCS_PLUS_256S_N;
pub const SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE: usize = 2 * SPHINCS_PLUS_256S_N;
pub const SPHINCS_PLUS_256S_SECRET_KEY_SIZE: usize =
    2 * SPHINCS_PLUS_256S_N + SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE;
pub const SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE: usize = 3 * SPHINCS_PLUS_256S_N;

const SPX_TREE_BITS: usize = SPX_TREE_HEIGHT as usize * (SPX_D as usize - 1);
const SPX_TREE_BYTES: usize = SPX_TREE_BITS.div_ceil(8);
const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT as usize;
const SPX_LEAF_BYTES: usize = SPX_LEAF_BITS.div_ceil(8);
const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES;

const SPX_OFFSET_LAYER: usize = 3;
const SPX_OFFSET_TREE: usize = 8;
const SPX_OFFSET_TYPE: usize = 19;
const SPX_OFFSET_KP_ADDR: usize = 20;
const SPX_OFFSET_CHAIN_ADDR: usize = 27;
const SPX_OFFSET_HASH_ADDR: usize = 31;
const SPX_OFFSET_TREE_HGT: usize = 27;
const SPX_OFFSET_TREE_INDEX: usize = 28;

const SPX_ADDR_TYPE_WOTS: u32 = 0;
const SPX_ADDR_TYPE_WOTSPK: u32 = 1;
const SPX_ADDR_TYPE_HASHTREE: u32 = 2;
const SPX_ADDR_TYPE_FORSTREE: u32 = 3;
const SPX_ADDR_TYPE_FORSPK: u32 = 4;
const SPX_ADDR_TYPE_WOTSPRF: u32 = 5;
const SPX_ADDR_TYPE_FORSPRF: u32 = 6;

#[derive(Clone, Debug)]
struct SPXCtx {
    pub_seed: [u8; SPHINCS_PLUS_256S_N],
    sk_seed: [u8; SPHINCS_PLUS_256S_N],
}

#[derive(Clone, Debug)]
pub struct SphincsPlus256s {
    pk: [u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
    sk: [u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE],
    seed: [u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE],
}

struct ForsGenLeafInfo {
    leaf_addr: [u32; 8],
}

struct LeafInfoX1<'a> {
    wots_sig: &'a mut [u8],
    wots_sign_leaf: u32,
    wots_steps: [u8; SPX_WOTS_LEN],
    leaf_addr: [u32; 8],
    pk_addr: [u32; 8],
}

fn trim_hex_prefix(value: &str) -> &str {
    value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value)
}

fn shake256(output: &mut [u8], input: &[u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

fn addr_to_bytes(addr: &[u32; 8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, value) in addr.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    output
}

fn bytes_to_addr(bytes: &[u8]) -> [u32; 8] {
    let mut addr = [0_u32; 8];
    for (index, chunk) in bytes.chunks_exact(4).take(8).enumerate() {
        // Invariant tripwire: `chunks_exact(4)` yields slices of exactly
        // 4 bytes (any tail shorter than 4 is discarded), so the
        // `&[u8] -> [u8; 4]` conversion below cannot fail at runtime.
        // The expect is the documented panic-policy "invariant violation"
        // shape — a tripwire against any future refactor that swaps the
        // chunk source for one with a different length guarantee. See
        // `SECURITY.md` "Audit-derived design choices" for the policy.
        addr[index] =
            u32::from_be_bytes(chunk.try_into().expect("chunks_exact(4) guarantees 4-byte chunks"));
    }
    addr
}

fn update_addr_byte(addr: &mut [u32; 8], offset: usize, value: u8) {
    let mut bytes = addr_to_bytes(addr);
    bytes[offset] = value;
    *addr = bytes_to_addr(&bytes);
}

fn set_layer_addr(addr: &mut [u32; 8], layer: u32) {
    update_addr_byte(addr, SPX_OFFSET_LAYER, layer as u8);
}

fn set_tree_addr(addr: &mut [u32; 8], tree: u64) {
    let mut bytes = addr_to_bytes(addr);
    bytes[SPX_OFFSET_TREE..SPX_OFFSET_TREE + 8].copy_from_slice(&tree.to_be_bytes());
    *addr = bytes_to_addr(&bytes);
}

fn set_type(addr: &mut [u32; 8], ty: u32) {
    update_addr_byte(addr, SPX_OFFSET_TYPE, ty as u8);
}

fn copy_subtree_addr(out: &mut [u32; 8], input: &[u32; 8]) {
    let input_bytes = addr_to_bytes(input);
    let mut output_bytes = addr_to_bytes(out);
    output_bytes[..SPX_OFFSET_TREE + 8].copy_from_slice(&input_bytes[..SPX_OFFSET_TREE + 8]);
    *out = bytes_to_addr(&output_bytes);
}

fn set_keypair_addr(addr: &mut [u32; 8], keypair: u32) {
    let mut bytes = addr_to_bytes(addr);
    bytes[SPX_OFFSET_KP_ADDR..SPX_OFFSET_KP_ADDR + 4].copy_from_slice(&keypair.to_be_bytes());
    *addr = bytes_to_addr(&bytes);
}

fn copy_keypair_addr(out: &mut [u32; 8], input: &[u32; 8]) {
    let input_bytes = addr_to_bytes(input);
    let mut output_bytes = addr_to_bytes(out);
    output_bytes[..SPX_OFFSET_TREE + 8].copy_from_slice(&input_bytes[..SPX_OFFSET_TREE + 8]);
    output_bytes[SPX_OFFSET_KP_ADDR..SPX_OFFSET_KP_ADDR + 4]
        .copy_from_slice(&input_bytes[SPX_OFFSET_KP_ADDR..SPX_OFFSET_KP_ADDR + 4]);
    *out = bytes_to_addr(&output_bytes);
}

fn memcpy_addr(out: &mut [u8], input: &[u32; 8]) {
    out[..32].copy_from_slice(&addr_to_bytes(input));
}

fn set_chain_addr(addr: &mut [u32; 8], chain: u32) {
    update_addr_byte(addr, SPX_OFFSET_CHAIN_ADDR, chain as u8);
}

fn set_hash_addr(addr: &mut [u32; 8], hash: u32) {
    update_addr_byte(addr, SPX_OFFSET_HASH_ADDR, hash as u8);
}

fn set_tree_height(addr: &mut [u32; 8], tree_height: u32) {
    update_addr_byte(addr, SPX_OFFSET_TREE_HGT, tree_height as u8);
}

fn set_tree_index(addr: &mut [u32; 8], tree_index: u32) {
    let mut bytes = addr_to_bytes(addr);
    bytes[SPX_OFFSET_TREE_INDEX..SPX_OFFSET_TREE_INDEX + 4]
        .copy_from_slice(&tree_index.to_be_bytes());
    *addr = bytes_to_addr(&bytes);
}

fn prf_addr(out: &mut [u8], ctx: &SPXCtx, addr: &[u32; 8]) {
    let mut buffer = [0_u8; 2 * SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES];
    buffer[..SPHINCS_PLUS_256S_N].copy_from_slice(&ctx.pub_seed);
    buffer[SPHINCS_PLUS_256S_N..SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES]
        .copy_from_slice(&addr_to_bytes(addr));
    buffer[SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES..].copy_from_slice(&ctx.sk_seed);
    shake256(&mut out[..SPHINCS_PLUS_256S_N], &buffer);
}

fn gen_message_random(r: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) {
    let mut hasher = Shake256::default();
    hasher.update(&sk_prf[..SPHINCS_PLUS_256S_N]);
    hasher.update(&opt_rand[..SPHINCS_PLUS_256S_N]);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut r[..SPHINCS_PLUS_256S_N]);
}

#[allow(clippy::too_many_arguments)]
fn hash_message(
    digest: &mut [u8],
    tree: &mut u64,
    leaf_idx: &mut u32,
    r: &[u8],
    pk: &[u8],
    message: &[u8],
) {
    let mut buffer = [0_u8; SPX_DGST_BYTES];
    let mut hasher = Shake256::default();
    hasher.update(&r[..SPHINCS_PLUS_256S_N]);
    hasher.update(&pk[..SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE]);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut buffer);

    let mut offset = 0;
    digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&buffer[offset..offset + SPX_FORS_MSG_BYTES]);
    offset += SPX_FORS_MSG_BYTES;

    *tree = bytes_to_ull(&buffer[offset..offset + SPX_TREE_BYTES]);
    *tree &= u64::MAX >> (64 - SPX_TREE_BITS);
    offset += SPX_TREE_BYTES;

    *leaf_idx = bytes_to_ull(&buffer[offset..offset + SPX_LEAF_BYTES]) as u32;
    *leaf_idx &= u32::MAX >> (32 - SPX_LEAF_BITS);
}

fn t_hash(out: &mut [u8], input: &[u8], in_blocks: usize, ctx: &SPXCtx, addr: &[u32; 8]) {
    let buf_len = SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES + in_blocks * SPHINCS_PLUS_256S_N;
    let mut buffer = vec![0_u8; buf_len];
    let mut bitmask = vec![0_u8; in_blocks * SPHINCS_PLUS_256S_N];

    buffer[..SPHINCS_PLUS_256S_N].copy_from_slice(&ctx.pub_seed);
    memcpy_addr(&mut buffer[SPHINCS_PLUS_256S_N..SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES], addr);
    shake256(&mut bitmask, &buffer[..SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES]);

    for (index, value) in bitmask.iter().enumerate() {
        buffer[SPHINCS_PLUS_256S_N + SPX_ADDR_BYTES + index] = input[index] ^ *value;
    }

    shake256(out, &buffer);
}

fn ull_to_bytes(out: &mut [u8], mut value: u64) {
    for item in out.iter_mut().rev() {
        *item = (value & 0xff) as u8;
        value >>= 8;
    }
}

fn bytes_to_ull(input: &[u8]) -> u64 {
    let mut output = 0_u64;
    for value in input {
        output = (output << 8) | u64::from(*value);
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn compute_root(
    root: &mut [u8],
    leaf: &[u8],
    mut leaf_idx: u32,
    mut idx_offset: u32,
    auth_path: &[u8],
    tree_height: u32,
    ctx: &SPXCtx,
    addr: &mut [u32; 8],
) {
    let mut auth_offset = 0_usize;
    let mut buffer = vec![0_u8; 2 * SPHINCS_PLUS_256S_N];

    if leaf_idx & 1 == 1 {
        buffer[..SPHINCS_PLUS_256S_N].copy_from_slice(&auth_path[..SPHINCS_PLUS_256S_N]);
        buffer[SPHINCS_PLUS_256S_N..].copy_from_slice(leaf);
    } else {
        buffer[..SPHINCS_PLUS_256S_N].copy_from_slice(leaf);
        buffer[SPHINCS_PLUS_256S_N..].copy_from_slice(&auth_path[..SPHINCS_PLUS_256S_N]);
    }
    auth_offset += SPHINCS_PLUS_256S_N;

    for height in 0..tree_height - 1 {
        leaf_idx >>= 1;
        idx_offset >>= 1;

        set_tree_height(addr, height + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        let current = buffer.clone();
        if leaf_idx & 1 == 1 {
            let mut output = vec![0_u8; SPHINCS_PLUS_256S_N];
            t_hash(&mut output, &current, 2, ctx, addr);
            buffer[SPHINCS_PLUS_256S_N..].copy_from_slice(&output);
            buffer[..SPHINCS_PLUS_256S_N]
                .copy_from_slice(&auth_path[auth_offset..auth_offset + SPHINCS_PLUS_256S_N]);
        } else {
            let mut output = vec![0_u8; SPHINCS_PLUS_256S_N];
            t_hash(&mut output, &current, 2, ctx, addr);
            buffer[..SPHINCS_PLUS_256S_N].copy_from_slice(&output);
            buffer[SPHINCS_PLUS_256S_N..]
                .copy_from_slice(&auth_path[auth_offset..auth_offset + SPHINCS_PLUS_256S_N]);
        }
        auth_offset += SPHINCS_PLUS_256S_N;
    }

    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    t_hash(root, &buffer, 2, ctx, addr);
}

fn gen_chain(
    out: &mut [u8],
    input: &[u8],
    start: usize,
    steps: usize,
    ctx: &SPXCtx,
    addr: &mut [u32; 8],
) {
    out[..SPHINCS_PLUS_256S_N].copy_from_slice(&input[..SPHINCS_PLUS_256S_N]);
    for index in start..(start + steps).min(SPX_WOTS_W) {
        set_hash_addr(addr, index as u32);
        let current = out[..SPHINCS_PLUS_256S_N].to_vec();
        t_hash(&mut out[..SPHINCS_PLUS_256S_N], &current, 1, ctx, addr);
    }
}

fn base_w(output: &mut [u8], out_len: usize, input: &[u8]) {
    let mut input_index = 0_usize;
    let mut total = 0_u8;
    let mut bits = 0_usize;

    for value in output.iter_mut().take(out_len) {
        if bits == 0 {
            total = input[input_index];
            input_index += 1;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        *value = (total >> bits) & (SPX_WOTS_W as u8 - 1);
    }
}

fn wots_checksum(csum_base_w: &mut [u8], msg_base_w: &[u8]) {
    let mut checksum = 0_u64;
    let mut checksum_bytes = vec![0_u8; (SPX_WOTS_LEN2 * SPX_WOTS_LOGW).div_ceil(8)];

    for value in msg_base_w.iter().take(SPX_WOTS_LEN1) {
        checksum += (SPX_WOTS_W - 1 - usize::from(*value)) as u64;
    }
    checksum <<= (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) as u64 % 8;
    ull_to_bytes(&mut checksum_bytes, checksum);
    base_w(csum_base_w, SPX_WOTS_LEN2, &checksum_bytes);
}

fn chain_lengths(lengths: &mut [u8], message: &[u8]) {
    base_w(&mut lengths[..SPX_WOTS_LEN1], SPX_WOTS_LEN1, message);
    let prefix = lengths[..SPX_WOTS_LEN1].to_vec();
    wots_checksum(&mut lengths[SPX_WOTS_LEN1..], &prefix);
}

fn wots_pk_from_sig(
    public_key: &mut [u8],
    signature: &[u8],
    message: &[u8],
    ctx: &SPXCtx,
    addr: &mut [u32; 8],
) {
    let mut lengths = [0_u8; SPX_WOTS_LEN];
    chain_lengths(&mut lengths, message);

    for (index, value) in lengths.iter().enumerate() {
        set_chain_addr(addr, index as u32);
        let start = index * SPHINCS_PLUS_256S_N;
        gen_chain(
            &mut public_key[start..start + SPHINCS_PLUS_256S_N],
            &signature[start..start + SPHINCS_PLUS_256S_N],
            usize::from(*value),
            SPX_WOTS_W - 1 - usize::from(*value),
            ctx,
            addr,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn tree_hash_x1<I, F>(
    root: &mut [u8],
    auth_path: &mut [u8],
    ctx: &SPXCtx,
    leaf_idx: u32,
    idx_offset: u32,
    tree_height: u32,
    mut gen_leaf: F,
    tree_addr: &mut [u32; 8],
    info: &mut I,
) where
    F: FnMut(&mut [u8], &SPXCtx, u32, &mut I),
{
    let mut stack = vec![0_u8; tree_height as usize * SPHINCS_PLUS_256S_N];
    let max_idx = (1_u32 << tree_height) - 1;

    let mut idx = 0_u32;
    loop {
        let mut current = vec![0_u8; 2 * SPHINCS_PLUS_256S_N];
        gen_leaf(&mut current[SPHINCS_PLUS_256S_N..], ctx, idx + idx_offset, info);

        let mut internal_idx_offset = idx_offset;
        let mut internal_idx = idx;
        let mut internal_leaf = leaf_idx;
        let mut height = 0_u32;

        loop {
            if height == tree_height {
                root.copy_from_slice(&current[SPHINCS_PLUS_256S_N..]);
                return;
            }

            if (internal_idx ^ internal_leaf) == 1 {
                let dest = height as usize * SPHINCS_PLUS_256S_N;
                auth_path[dest..dest + SPHINCS_PLUS_256S_N]
                    .copy_from_slice(&current[SPHINCS_PLUS_256S_N..]);
            }

            if (internal_idx & 1) == 0 && idx < max_idx {
                break;
            }

            internal_idx_offset >>= 1;
            set_tree_height(tree_addr, height + 1);
            set_tree_index(tree_addr, internal_idx / 2 + internal_idx_offset);

            let left_start = height as usize * SPHINCS_PLUS_256S_N;
            current[..SPHINCS_PLUS_256S_N]
                .copy_from_slice(&stack[left_start..left_start + SPHINCS_PLUS_256S_N]);
            let input = current.clone();
            let mut output = vec![0_u8; SPHINCS_PLUS_256S_N];
            t_hash(&mut output, &input, 2, ctx, tree_addr);
            current[SPHINCS_PLUS_256S_N..].copy_from_slice(&output);

            height += 1;
            internal_idx >>= 1;
            internal_leaf >>= 1;
        }

        let stack_start = height as usize * SPHINCS_PLUS_256S_N;
        stack[stack_start..stack_start + SPHINCS_PLUS_256S_N]
            .copy_from_slice(&current[SPHINCS_PLUS_256S_N..]);
        idx += 1;
    }
}

fn fors_gen_sk(secret_key: &mut [u8], ctx: &SPXCtx, fors_leaf_addr: &[u32; 8]) {
    prf_addr(secret_key, ctx, fors_leaf_addr);
}

fn fors_sk_to_leaf(leaf: &mut [u8], secret_key: &[u8], ctx: &SPXCtx, fors_leaf_addr: &[u32; 8]) {
    t_hash(leaf, secret_key, 1, ctx, fors_leaf_addr);
}

fn fors_gen_leaf_x1(leaf: &mut [u8], ctx: &SPXCtx, addr_idx: u32, info: &mut ForsGenLeafInfo) {
    let fors_leaf_addr = &mut info.leaf_addr;
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    let current = leaf.to_vec();
    fors_sk_to_leaf(leaf, &current, ctx, fors_leaf_addr);
}

fn message_to_indices(indices: &mut [u32; SPX_FORS_TREES], message: &[u8]) {
    let mut offset = 0_usize;
    for index in indices.iter_mut() {
        *index = 0;
        for bit_index in 0..SPX_FORS_HEIGHT {
            let byte_idx = offset >> 3;
            let bit_offset = 7 - (offset & 0x7);
            let bit = (message[byte_idx] >> bit_offset) & 1;
            let shift = (SPX_FORS_HEIGHT - 1 - bit_index) as u32;
            *index ^= u32::from(bit) << shift;
            offset += 1;
        }
    }
}

fn fors_sign(
    sig: &mut [u8],
    public_key: &mut [u8],
    message: &[u8],
    ctx: &SPXCtx,
    fors_addr: &mut [u32; 8],
) {
    let mut indices = [0_u32; SPX_FORS_TREES];
    let mut roots = vec![0_u8; SPX_FORS_TREES * SPHINCS_PLUS_256S_N];

    let mut fors_tree_addr = [0_u32; 8];
    let mut fors_leaf_info = ForsGenLeafInfo { leaf_addr: [0_u32; 8] };
    let mut fors_pk_addr = [0_u32; 8];

    copy_keypair_addr(&mut fors_tree_addr, fors_addr);
    copy_keypair_addr(&mut fors_leaf_info.leaf_addr, fors_addr);
    copy_keypair_addr(&mut fors_pk_addr, fors_addr);
    set_type(&mut fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(&mut indices, message);

    let mut sig_offset = 0_usize;
    for (tree_index, leaf_index) in indices.iter().enumerate() {
        let idx_offset = (tree_index as u32) * (1 << SPX_FORS_HEIGHT);

        set_tree_height(&mut fors_tree_addr, 0);
        set_tree_index(&mut fors_tree_addr, *leaf_index + idx_offset);
        set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        fors_gen_sk(&mut sig[sig_offset..sig_offset + SPHINCS_PLUS_256S_N], ctx, &fors_tree_addr);
        sig_offset += SPHINCS_PLUS_256S_N;

        set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        tree_hash_x1(
            &mut roots[tree_index * SPHINCS_PLUS_256S_N..(tree_index + 1) * SPHINCS_PLUS_256S_N],
            &mut sig[sig_offset..sig_offset + SPHINCS_PLUS_256S_N * SPX_FORS_HEIGHT],
            ctx,
            *leaf_index,
            idx_offset,
            SPX_FORS_HEIGHT as u32,
            fors_gen_leaf_x1,
            &mut fors_tree_addr,
            &mut fors_leaf_info,
        );
        sig_offset += SPHINCS_PLUS_256S_N * SPX_FORS_HEIGHT;
    }

    t_hash(public_key, &roots, SPX_FORS_TREES, ctx, &fors_pk_addr);
}

fn fors_pk_from_sig(
    public_key: &mut [u8],
    signature: &[u8],
    message: &[u8],
    ctx: &SPXCtx,
    fors_addr: &mut [u32; 8],
) {
    let mut indices = [0_u32; SPX_FORS_TREES];
    let mut roots = vec![0_u8; SPX_FORS_TREES * SPHINCS_PLUS_256S_N];
    let mut leaf = vec![0_u8; SPHINCS_PLUS_256S_N];

    let mut fors_tree_addr = [0_u32; 8];
    let mut fors_pk_addr = [0_u32; 8];
    copy_keypair_addr(&mut fors_tree_addr, fors_addr);
    copy_keypair_addr(&mut fors_pk_addr, fors_addr);
    set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(&mut fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(&mut indices, message);

    let mut sig_offset = 0_usize;
    for (tree_index, leaf_index) in indices.iter().enumerate() {
        let idx_offset = (tree_index as u32) * (1 << SPX_FORS_HEIGHT);
        set_tree_height(&mut fors_tree_addr, 0);
        set_tree_index(&mut fors_tree_addr, *leaf_index + idx_offset);

        fors_sk_to_leaf(
            &mut leaf,
            &signature[sig_offset..sig_offset + SPHINCS_PLUS_256S_N],
            ctx,
            &fors_tree_addr,
        );
        sig_offset += SPHINCS_PLUS_256S_N;

        compute_root(
            &mut roots[tree_index * SPHINCS_PLUS_256S_N..(tree_index + 1) * SPHINCS_PLUS_256S_N],
            &leaf,
            *leaf_index,
            idx_offset,
            &signature[sig_offset..sig_offset + SPHINCS_PLUS_256S_N * SPX_FORS_HEIGHT],
            SPX_FORS_HEIGHT as u32,
            ctx,
            &mut fors_tree_addr,
        );
        sig_offset += SPHINCS_PLUS_256S_N * SPX_FORS_HEIGHT;
    }

    t_hash(public_key, &roots, SPX_FORS_TREES, ctx, &fors_pk_addr);
}

fn wots_gen_leaf_x1(dest: &mut [u8], ctx: &SPXCtx, leaf_idx: u32, info: &mut LeafInfoX1<'_>) {
    let leaf_addr = &mut info.leaf_addr;
    let pk_addr = &mut info.pk_addr;
    let mut public_key_buffer = [0_u8; SPX_WOTS_BYTES];

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for index in 0..SPX_WOTS_LEN {
        let offset = index * SPHINCS_PLUS_256S_N;
        let chain = &mut public_key_buffer[offset..offset + SPHINCS_PLUS_256S_N];

        set_chain_addr(leaf_addr, index as u32);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);
        prf_addr(chain, ctx, leaf_addr);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        let step = info.wots_steps[index];
        for hash_index in 0..SPX_WOTS_W as u8 {
            if leaf_idx == info.wots_sign_leaf && hash_index == step {
                info.wots_sig[offset..offset + SPHINCS_PLUS_256S_N].copy_from_slice(chain);
            }
            if hash_index == SPX_WOTS_W as u8 - 1 {
                break;
            }
            set_hash_addr(leaf_addr, u32::from(hash_index));
            let current = chain.to_vec();
            t_hash(chain, &current, 1, ctx, leaf_addr);
        }
    }

    t_hash(dest, &public_key_buffer, SPX_WOTS_LEN, ctx, pk_addr);
}

fn merkle_sign(
    sig: &mut [u8],
    root: &mut [u8],
    ctx: &SPXCtx,
    wots_addr: &mut [u32; 8],
    tree_addr: &mut [u32; 8],
    idx_leaf: u32,
) {
    let (wots_sig, auth_path) = sig.split_at_mut(SPX_WOTS_BYTES);
    let mut steps = [0_u8; SPX_WOTS_LEN];
    chain_lengths(&mut steps, root);

    let mut info = LeafInfoX1 {
        wots_sig,
        wots_sign_leaf: idx_leaf,
        wots_steps: steps,
        leaf_addr: [0_u32; 8],
        pk_addr: [0_u32; 8],
    };

    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(&mut info.pk_addr, SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&mut info.leaf_addr, wots_addr);
    copy_subtree_addr(&mut info.pk_addr, wots_addr);

    tree_hash_x1(
        root,
        auth_path,
        ctx,
        idx_leaf,
        0,
        SPX_TREE_HEIGHT,
        wots_gen_leaf_x1,
        tree_addr,
        &mut info,
    );
}

fn merkle_gen_root(root: &mut [u8], ctx: &SPXCtx) {
    let mut auth_path = vec![0_u8; SPX_TREE_HEIGHT as usize * SPHINCS_PLUS_256S_N + SPX_WOTS_BYTES];
    let mut top_tree_addr = [0_u32; 8];
    let mut wots_addr = [0_u32; 8];
    set_layer_addr(&mut top_tree_addr, SPX_D - 1);
    set_layer_addr(&mut wots_addr, SPX_D - 1);
    merkle_sign(&mut auth_path, root, ctx, &mut wots_addr, &mut top_tree_addr, u32::MAX);
}

fn crypto_sign_seed_keypair(
    public_key: &mut [u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE],
    secret_key: &mut [u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE],
    seed: &[u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE],
) {
    secret_key[..SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE].copy_from_slice(seed);
    public_key[..SPHINCS_PLUS_256S_N]
        .copy_from_slice(&secret_key[2 * SPHINCS_PLUS_256S_N..3 * SPHINCS_PLUS_256S_N]);

    let mut ctx =
        SPXCtx { pub_seed: [0_u8; SPHINCS_PLUS_256S_N], sk_seed: [0_u8; SPHINCS_PLUS_256S_N] };
    ctx.pub_seed.copy_from_slice(&public_key[..SPHINCS_PLUS_256S_N]);
    ctx.sk_seed.copy_from_slice(&secret_key[..SPHINCS_PLUS_256S_N]);

    merkle_gen_root(&mut secret_key[3 * SPHINCS_PLUS_256S_N..], &ctx);
    public_key[SPHINCS_PLUS_256S_N..].copy_from_slice(&secret_key[3 * SPHINCS_PLUS_256S_N..]);

    ctx.sk_seed.zeroize();
}

fn fill_random_optrand(output: &mut [u8; SPHINCS_PLUS_256S_N]) -> Result<()> {
    getrandom::getrandom(output)?;
    Ok(())
}

fn crypto_sign_signature(
    sig: &mut [u8],
    message: &[u8],
    secret_key: &[u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE],
    optrand_override: Option<&[u8; SPHINCS_PLUS_256S_N]>,
) -> Result<()> {
    let mut any_nonzero = 0_u8;
    for byte in secret_key.iter() {
        any_nonzero |= byte;
    }
    if any_nonzero == 0 {
        return Err(QrllibError::SphincsPlusSecretKeyZeroized);
    }

    let sk_prf = &secret_key[SPHINCS_PLUS_256S_N..2 * SPHINCS_PLUS_256S_N];
    let pk = &secret_key[2 * SPHINCS_PLUS_256S_N..4 * SPHINCS_PLUS_256S_N];

    let mut opt_rand = [0_u8; SPHINCS_PLUS_256S_N];
    let mut message_hash = [0_u8; SPX_FORS_MSG_BYTES];
    let mut root = [0_u8; SPHINCS_PLUS_256S_N];
    let mut tree = 0_u64;
    let mut idx_leaf = 0_u32;
    let mut wots_addr = [0_u32; 8];
    let mut tree_addr = [0_u32; 8];

    let mut ctx =
        SPXCtx { pub_seed: [0_u8; SPHINCS_PLUS_256S_N], sk_seed: [0_u8; SPHINCS_PLUS_256S_N] };
    ctx.sk_seed.copy_from_slice(&secret_key[..SPHINCS_PLUS_256S_N]);
    ctx.pub_seed.copy_from_slice(&pk[..SPHINCS_PLUS_256S_N]);

    set_type(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);

    if let Some(optrand) = optrand_override {
        opt_rand.copy_from_slice(optrand);
    } else if let Err(error) = fill_random_optrand(&mut opt_rand) {
        // Coverage: the RNG-failure arm is unreachable in tests — `getrandom`
        // only errors on OS-level RNG exhaustion. Kept so that catastrophic
        // RNG failures zeroize the secret-key material before propagating.
        ctx.sk_seed.zeroize();
        opt_rand.zeroize();
        return Err(error);
    }
    gen_message_random(&mut sig[..SPHINCS_PLUS_256S_N], sk_prf, &opt_rand, message);
    hash_message(
        &mut message_hash,
        &mut tree,
        &mut idx_leaf,
        &sig[..SPHINCS_PLUS_256S_N],
        pk,
        message,
    );

    let mut sig_offset = SPHINCS_PLUS_256S_N;
    set_tree_addr(&mut wots_addr, tree);
    set_keypair_addr(&mut wots_addr, idx_leaf);

    fors_sign(
        &mut sig[sig_offset..sig_offset + SPX_FORS_BYTES],
        &mut root,
        &message_hash,
        &ctx,
        &mut wots_addr,
    );
    sig_offset += SPX_FORS_BYTES;

    for layer in 0..SPX_D {
        set_layer_addr(&mut tree_addr, layer);
        set_tree_addr(&mut tree_addr, tree);
        copy_subtree_addr(&mut wots_addr, &tree_addr);
        set_keypair_addr(&mut wots_addr, idx_leaf);

        merkle_sign(
            &mut sig[sig_offset
                ..sig_offset + SPX_WOTS_BYTES + SPX_TREE_HEIGHT as usize * SPHINCS_PLUS_256S_N],
            &mut root,
            &ctx,
            &mut wots_addr,
            &mut tree_addr,
            idx_leaf,
        );
        sig_offset += SPX_WOTS_BYTES + SPX_TREE_HEIGHT as usize * SPHINCS_PLUS_256S_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree >>= SPX_TREE_HEIGHT;
    }

    ctx.sk_seed.zeroize();
    opt_rand.zeroize();
    Ok(())
}

fn crypto_sign(
    message: &[u8],
    secret_key: &[u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE],
) -> Result<Vec<u8>> {
    let mut signature_message = vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE + message.len()];
    crypto_sign_signature(
        &mut signature_message[..SPHINCS_PLUS_256S_SIGNATURE_SIZE],
        message,
        secret_key,
        None,
    )?;
    signature_message[SPHINCS_PLUS_256S_SIGNATURE_SIZE..].copy_from_slice(message);
    Ok(signature_message)
}

// Defensive length guard never fires when called from SPHINCS+ internals
// (both operands are compile-time-sized arrays). Semantics verified via
// higher-level signature-verify tests that exercise equal / mismatched bytes.
#[cfg_attr(coverage_nightly, coverage(off))]
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

fn crypto_sign_verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != SPHINCS_PLUS_256S_SIGNATURE_SIZE
        || public_key.len() != SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE
    {
        return false;
    }

    let pub_root = &public_key[SPHINCS_PLUS_256S_N..];
    let mut message_hash = [0_u8; SPX_FORS_MSG_BYTES];
    let mut wots_public_key = [0_u8; SPX_WOTS_BYTES];
    let mut root = [0_u8; SPHINCS_PLUS_256S_N];
    let mut leaf = [0_u8; SPHINCS_PLUS_256S_N];

    let mut tree = 0_u64;
    let mut idx_leaf = 0_u32;
    let mut wots_addr = [0_u32; 8];
    let mut tree_addr = [0_u32; 8];
    let mut wots_pk_addr = [0_u32; 8];
    let mut ctx =
        SPXCtx { pub_seed: [0_u8; SPHINCS_PLUS_256S_N], sk_seed: [0_u8; SPHINCS_PLUS_256S_N] };
    ctx.pub_seed.copy_from_slice(&public_key[..SPHINCS_PLUS_256S_N]);

    set_type(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(&mut wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    hash_message(&mut message_hash, &mut tree, &mut idx_leaf, signature, public_key, message);

    let mut sig_offset = SPHINCS_PLUS_256S_N;
    set_tree_addr(&mut wots_addr, tree);
    set_keypair_addr(&mut wots_addr, idx_leaf);

    fors_pk_from_sig(
        &mut root,
        &signature[sig_offset..sig_offset + SPX_FORS_BYTES],
        &message_hash,
        &ctx,
        &mut wots_addr,
    );
    sig_offset += SPX_FORS_BYTES;

    for layer in 0..SPX_D {
        set_layer_addr(&mut tree_addr, layer);
        set_tree_addr(&mut tree_addr, tree);

        copy_subtree_addr(&mut wots_addr, &tree_addr);
        set_keypair_addr(&mut wots_addr, idx_leaf);
        copy_keypair_addr(&mut wots_pk_addr, &wots_addr);

        wots_pk_from_sig(
            &mut wots_public_key,
            &signature[sig_offset..sig_offset + SPX_WOTS_BYTES],
            &root,
            &ctx,
            &mut wots_addr,
        );
        sig_offset += SPX_WOTS_BYTES;

        t_hash(&mut leaf, &wots_public_key, SPX_WOTS_LEN, &ctx, &wots_pk_addr);
        compute_root(
            &mut root,
            &leaf,
            idx_leaf,
            0,
            &signature[sig_offset..sig_offset + SPX_TREE_HEIGHT as usize * SPHINCS_PLUS_256S_N],
            SPX_TREE_HEIGHT,
            &ctx,
            &mut tree_addr,
        );
        sig_offset += SPX_TREE_HEIGHT as usize * SPHINCS_PLUS_256S_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree >>= SPX_TREE_HEIGHT;
    }

    constant_time_eq(&root, pub_root)
}

// Thin shim over `crypto_sign_verify`; its defensive length guard is duplicated
// from the public `sphincsplus_open` wrapper and can never fire from there.
// Verification semantics are measured via `verify_sphincsplus_signature` tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn crypto_sign_open(message: &mut [u8], signature_message: &[u8], public_key: &[u8]) -> bool {
    if signature_message.len() < SPHINCS_PLUS_256S_SIGNATURE_SIZE {
        return false;
    }
    if !crypto_sign_verify(
        &signature_message[..SPHINCS_PLUS_256S_SIGNATURE_SIZE],
        &signature_message[SPHINCS_PLUS_256S_SIGNATURE_SIZE..],
        public_key,
    ) {
        return false;
    }
    message.copy_from_slice(&signature_message[SPHINCS_PLUS_256S_SIGNATURE_SIZE..]);
    true
}

impl SphincsPlus256s {
    pub fn generate() -> Result<Self> {
        let mut seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        getrandom::getrandom(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE]) -> Self {
        let mut public_key = [0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE];
        let mut secret_key = [0_u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE];
        crypto_sign_seed_keypair(&mut public_key, &mut secret_key, &seed);
        Self { pk: public_key, sk: secret_key, seed }
    }

    pub fn from_hex_seed(value: &str) -> Result<Self> {
        // Map the decode failure to the sanitized sentinel rather than
        // propagating `hex::FromHexError`, whose Display echoes the offending
        // input character — the input is secret seed material (06-2026 audit fix).
        let bytes = hex::decode(trim_hex_prefix(value)).map_err(|_| QrllibError::InvalidHexSeed)?;
        if bytes.len() != SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE {
            return Err(QrllibError::InvalidSphincsSeedSize(
                bytes.len(),
                SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE,
            ));
        }

        let mut seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(seed))
    }

    /// Returns a zeroizing copy of the SPHINCS+ seed material.
    pub fn seed(&self) -> Zeroizing<[u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE]> {
        Zeroizing::new(self.seed)
    }

    pub fn public_key_bytes(&self) -> [u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE] {
        self.pk
    }

    /// Returns a zeroizing copy of the packed secret key.
    pub fn secret_key_bytes(&self) -> Zeroizing<[u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE]> {
        Zeroizing::new(self.sk)
    }

    pub fn hex_seed(&self) -> String {
        format!("0x{}", hex::encode(self.seed))
    }

    pub fn sign_attached(&self, message: &[u8]) -> Result<Vec<u8>> {
        crypto_sign(message, &self.sk)
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE]> {
        let mut signature = [0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE];
        crypto_sign_signature(&mut signature, message, &self.sk, None)?;
        Ok(signature)
    }

    pub fn zeroize(&mut self) {
        self.seed.zeroize();
        self.sk.zeroize();
    }
}

impl Drop for SphincsPlus256s {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn verify_sphincsplus_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    crypto_sign_verify(signature, message, public_key)
}

pub fn sphincsplus_open(signature_message: &[u8], public_key: &[u8]) -> Option<Vec<u8>> {
    if public_key.len() != SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE
        || signature_message.len() < SPHINCS_PLUS_256S_SIGNATURE_SIZE
    {
        return None;
    }
    let mut message = vec![0_u8; signature_message.len() - SPHINCS_PLUS_256S_SIGNATURE_SIZE];
    if crypto_sign_open(&mut message, signature_message, public_key) { Some(message) } else { None }
}

pub fn sphincsplus_extract_message(signature_message: &[u8]) -> Option<&[u8]> {
    if signature_message.len() < SPHINCS_PLUS_256S_SIGNATURE_SIZE {
        None
    } else {
        Some(&signature_message[SPHINCS_PLUS_256S_SIGNATURE_SIZE..])
    }
}

pub fn sphincsplus_extract_signature(signature_message: &[u8]) -> Option<&[u8]> {
    if signature_message.len() < SPHINCS_PLUS_256S_SIGNATURE_SIZE {
        None
    } else {
        Some(&signature_message[..SPHINCS_PLUS_256S_SIGNATURE_SIZE])
    }
}

pub fn validate_sphincsplus_public_key(public_key: &[u8]) -> Result<()> {
    if public_key.len() != SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE {
        return Err(QrllibError::InvalidPublicKeySize {
            wallet_type: WalletType::SphincsPlus256s,
            actual: public_key.len(),
            expected: SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
        SPHINCS_PLUS_256S_SECRET_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s,
        crypto_sign_signature, sphincsplus_extract_message, sphincsplus_extract_signature,
        sphincsplus_open, validate_sphincsplus_public_key, verify_sphincsplus_signature,
    };
    use crate::QrllibError;
    use sha2::Digest;

    fn known_seed() -> [u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE] {
        let mut seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        let bytes = hex::decode("816af0680147304a37f2188941b90b04286622dc48381a720f95e3cf043132da2c19c010a7bf8aabbe799509a2413aba3bc0832575cddad6c4e4fa108b5d45121d72a342d764d879ca4bf028064ff0b8f578c41bce0f52ed588dfe615d8d4a5c").expect("seed");
        seed.copy_from_slice(&bytes);
        seed
    }

    #[test]
    fn sphincsplus_known_seed_matches_go_keypair_vectors() {
        let signer = SphincsPlus256s::from_seed(known_seed());
        assert_eq!(
            hex::encode(signer.public_key_bytes()),
            "1d72a342d764d879ca4bf028064ff0b8f578c41bce0f52ed588dfe615d8d4a5cd824360629d606b24f0dbc677a89c05fb9912e146bc0b9d212d2506f571cbcea"
        );
        assert_eq!(
            hex::encode(signer.secret_key_bytes()),
            "816af0680147304a37f2188941b90b04286622dc48381a720f95e3cf043132da2c19c010a7bf8aabbe799509a2413aba3bc0832575cddad6c4e4fa108b5d45121d72a342d764d879ca4bf028064ff0b8f578c41bce0f52ed588dfe615d8d4a5cd824360629d606b24f0dbc677a89c05fb9912e146bc0b9d212d2506f571cbcea"
        );
    }

    #[test]
    fn sphincsplus_deterministic_signature_matches_go_vector_digest() {
        let signer = SphincsPlus256s::from_seed(known_seed());
        let message =
            hex::decode("ed3bead44dc0a0c0a0c1052a91372f1e93f49a76cc0a1e76dd2b39f73b8af88c")
                .expect("message");
        let mut signature = [0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE];
        let mut opt_rand = [0_u8; 32];
        let opt_rand_bytes =
            hex::decode("efec42e71cfe44ccb8100e10b7012a116203bb7ccbce6ebccc23573d07904f39")
                .expect("optrand");
        opt_rand.copy_from_slice(&opt_rand_bytes);

        crypto_sign_signature(&mut signature, &message, &signer.sk, Some(&opt_rand))
            .expect("deterministic signature");
        let mut sealed = signature.to_vec();
        sealed.extend_from_slice(&message);
        assert!(verify_sphincsplus_signature(&message, &signature, &signer.public_key_bytes(),));
        assert_eq!(sphincsplus_extract_message(&sealed).expect("message"), message.as_slice());
        assert_eq!(
            sphincsplus_extract_signature(&sealed).expect("signature"),
            signature.as_slice()
        );
        assert_eq!(sphincsplus_open(&sealed, &signer.public_key_bytes()).expect("opened"), message);
        assert!(
            sphincsplus_open(
                &sealed[..SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1],
                &signer.public_key_bytes()
            )
            .is_none()
        );
        assert!(
            sphincsplus_extract_message(&signature[..SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1])
                .is_none()
        );
        assert!(
            sphincsplus_extract_signature(&signature[..SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1])
                .is_none()
        );

        let digest = sha2::Sha256::digest(&sealed);
        assert_eq!(
            hex::encode(digest),
            "f7d04a265ace914b0422218d0d2a7ff88f5f810f9263c9c8b4e9980eadef1e16"
        );
    }

    #[test]
    fn sphincsplus_public_api_covers_hex_sizes_and_zeroize() {
        let signer = SphincsPlus256s::from_seed(known_seed());
        let hex_seed = signer.hex_seed();
        let imported = SphincsPlus256s::from_hex_seed(&hex_seed).expect("from hex");
        assert_eq!(imported.seed(), signer.seed());
        assert_eq!(imported.public_key_bytes(), signer.public_key_bytes());
        assert_eq!(imported.secret_key_bytes().len(), SPHINCS_PLUS_256S_SECRET_KEY_SIZE);
        assert_eq!(imported.public_key_bytes().len(), SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE);
        assert!(matches!(
            SphincsPlus256s::from_hex_seed("0x00"),
            Err(QrllibError::InvalidSphincsSeedSize(1, SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE))
        ));
        assert!(validate_sphincsplus_public_key(&imported.public_key_bytes()).is_ok());
        assert!(matches!(
            validate_sphincsplus_public_key(&[0_u8; 1]),
            Err(QrllibError::InvalidPublicKeySize { .. })
        ));

        let mut zeroized = imported.clone();
        zeroized.zeroize();
        assert!(zeroized.seed().iter().all(|byte| *byte == 0));
        assert!(zeroized.secret_key_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sphincsplus_sign_and_seal_reject_zeroized_secret_key() {
        let mut signer = SphincsPlus256s::from_seed(known_seed());
        signer.zeroize();
        assert!(matches!(
            signer.sign(b"after zeroize"),
            Err(QrllibError::SphincsPlusSecretKeyZeroized)
        ));
        assert!(matches!(
            signer.sign_attached(b"after zeroize"),
            Err(QrllibError::SphincsPlusSecretKeyZeroized)
        ));
    }
}
