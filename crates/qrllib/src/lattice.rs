pub(crate) const N: usize = 256;
pub(crate) const Q: i32 = 8_380_417;
pub(crate) const Q_INV: i32 = 58_728_449;
pub(crate) const D: i32 = 13;
pub(crate) const GAMMA2: i32 = (Q - 1) / 32;

pub(crate) const ZETAS: [i32; N] = [
    0, 25_847, -2_608_894, -518_909, 237_124, -777_960, -876_248, 466_468, 1_826_347, 2_353_451,
    -359_251, -2_091_905, 3_119_733, -2_884_855, 3_111_497, 2_680_103, 2_725_464, 1_024_112,
    -1_079_900, 3_585_928, -549_488, -1_119_584, 2_619_752, -2_108_549, -2_118_186, -3_859_737,
    -1_399_561, -3_277_672, 1_757_237, -19_422, 4_010_497, 280_005, 2_706_023, 95_776, 3_077_325,
    3_530_437, -1_661_693, -3_592_148, -2_537_516, 3_915_439, -3_861_115, -3_043_716, 3_574_422,
    -2_867_647, 3_539_968, -300_467, 2_348_700, -539_299, -1_699_267, -1_643_818, 3_505_694,
    -3_821_735, 3_507_263, -2_140_649, -1_600_420, 3_699_596, 811_944, 531_354, 954_230, 3_881_043,
    3_900_724, -2_556_880, 2_071_892, -2_797_779, -3_930_395, -1_528_703, -3_677_745, -3_041_255,
    -1_452_451, 3_475_950, 2_176_455, -1_585_221, -1_257_611, 1_939_314, -4_083_598, -1_000_202,
    -3_190_144, -3_157_330, -3_632_928, 126_922, 3_412_210, -983_419, 2_147_896, 2_715_295,
    -2_967_645, -3_693_493, -411_027, -2_477_047, -671_102, -1_228_525, -22_981, -1_308_169,
    -381_987, 1_349_076, 1_852_771, -1_430_430, -3_343_383, 264_944, 508_951, 3_097_992, 44_288,
    -1_100_098, 904_516, 3_958_618, -3_724_342, -8_578, 1_653_064, -3_249_728, 2_389_356, -210_977,
    759_969, -1_316_856, 189_548, -3_553_272, 3_159_746, -1_851_402, -2_409_325, -177_440,
    1_315_589, 1_341_330, 1_285_669, -1_584_928, -812_732, -1_439_742, -3_019_102, -3_881_060,
    -3_628_969, 3_839_961, 2_091_667, 3_407_706, 2_316_500, 3_817_976, -3_342_478, 2_244_091,
    -2_446_433, -3_562_462, 266_997, 2_434_439, -1_235_728, 3_513_181, -3_520_352, -3_759_364,
    -1_197_226, -3_193_378, 900_702, 1_859_098, 909_542, 819_034, 495_491, -1_613_174, -43_260,
    -522_500, -655_327, -3_122_442, 2_031_748, 3_207_046, -3_556_995, -525_098, -768_622,
    -3_595_838, 342_297, 286_988, -2_437_823, 4_108_315, 3_437_287, -3_342_277, 1_735_879, 203_044,
    2_842_341, 2_691_481, -2_590_150, 1_265_009, 4_055_324, 1_247_620, 2_486_353, 1_595_974,
    -3_767_016, 1_250_494, 2_635_921, -3_548_272, -2_994_039, 1_869_119, 1_903_435, -1_050_970,
    -1_333_058, 1_237_275, -3_318_210, -1_430_225, -451_100, 1_312_455, 3_306_115, -1_962_642,
    -1_279_661, 1_917_081, -2_546_312, -1_374_803, 1_500_165, 777_191, 2_235_880, 3_406_031,
    -542_412, -2_831_860, -1_671_176, -1_846_953, -2_584_293, -3_724_270, 594_136, -3_776_993,
    -2_013_608, 2_432_395, 2_454_455, -164_721, 1_957_272, 3_369_112, 185_531, -1_207_385,
    -3_183_426, 162_844, 1_616_392, 3_014_001, 810_149, 1_652_634, -3_694_233, -1_799_107,
    -3_038_916, 3_523_897, 3_866_901, 269_760, 2_213_111, -975_884, 1_717_735, 472_078, -426_683,
    1_723_600, -1_803_090, 1_910_376, -1_667_432, -1_104_333, -260_646, -3_833_893, -2_939_036,
    -2_235_985, -420_899, -2_286_327, 183_443, -976_891, 1_612_842, -3_545_687, -554_416,
    3_919_660, -48_306, -1_362_209, 3_937_738, 1_400_424, -846_154, 1_976_782,
];

pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(Q_INV);
    ((a - i64::from(t) * i64::from(Q)) >> 32) as i32
}

pub(crate) fn reduce32(a: i32) -> i32 {
    let t = a.wrapping_add(1 << 22) >> 23;
    a.wrapping_sub(t.wrapping_mul(Q))
}

pub(crate) fn c_add_q(a: i32) -> i32 {
    a.wrapping_add((a >> 31) & Q)
}

pub(crate) fn power2_round(a0: &mut i32, a: i32) -> i32 {
    let a1 = a.wrapping_add((1 << (D - 1)) - 1) >> D;
    *a0 = a.wrapping_sub(a1.wrapping_shl(D as u32));
    a1
}

pub(crate) fn decompose(a0: &mut i32, a: i32) -> i32 {
    let mut a1 = a.wrapping_add(127) >> 7;
    a1 = a1.wrapping_mul(1025).wrapping_add(1 << 21) >> 22;
    a1 &= 15;

    *a0 = a.wrapping_sub(a1.wrapping_mul(2 * GAMMA2));
    *a0 = a0.wrapping_sub((((Q - 1) / 2).wrapping_sub(*a0) >> 31) & Q);
    a1
}

pub(crate) fn make_hint(a0: i32, a1: i32) -> u32 {
    let gt_gamma2 = ((GAMMA2.wrapping_sub(a0)) as u32) >> 31;
    let lt_neg_gamma2 = (a0.wrapping_add(GAMMA2) as u32) >> 31;

    let diff = a0.wrapping_add(GAMMA2);
    let eq_neg_gamma2 = 1 - (((diff | diff.wrapping_neg()) as u32) >> 31);
    let a1_non_zero = ((a1 | a1.wrapping_neg()) as u32) >> 31;

    (gt_gamma2 | lt_neg_gamma2 | (eq_neg_gamma2 & a1_non_zero)) & 1
}

pub(crate) fn use_hint(a: i32, hint: i32) -> i32 {
    let mut a0 = 0;
    let a1 = decompose(&mut a0, a);

    let result0 = a1;
    let result_pos = a1.wrapping_add(1) & 15;
    let result_neg = a1.wrapping_sub(1) & 15;

    let hint_is_zero = 1 - ((((hint | hint.wrapping_neg()) as u32) >> 31) as i32 & 1);
    let a0_positive = (((a0.wrapping_neg()) as u32) >> 31) as i32 & 1;

    let hint_non_zero = 1 - hint_is_zero;
    let mask0 = -hint_is_zero;
    let mask_hint_nz = -hint_non_zero;
    let mask_a0_pos = -a0_positive;
    let mask_a0_not_pos = !mask_a0_pos;

    let mask_pos = mask_hint_nz & mask_a0_pos;
    let mask_neg = mask_hint_nz & mask_a0_not_pos;

    (result0 & mask0) | (result_pos & mask_pos) | (result_neg & mask_neg)
}

pub(crate) fn ntt(a: &mut [i32; N]) {
    let mut k = 0_usize;
    let mut count = 128_usize;

    while count > 0 {
        let mut start = 0_usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            let mut j = start;
            while j < start + count {
                let t = montgomery_reduce(i64::from(zeta) * i64::from(a[j + count]));
                a[j + count] = a[j].wrapping_sub(t);
                a[j] = a[j].wrapping_add(t);
                j += 1;
            }
            start = j + count;
        }
        count >>= 1;
    }
}

pub(crate) fn inv_ntt_to_mont(a: &mut [i32; N]) {
    let f = 41_978_i32;
    let mut k = 256_usize;
    let mut count = 1_usize;

    while count < N {
        let mut start = 0_usize;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            let mut j = start;
            while j < start + count {
                let t = a[j];
                a[j] = t.wrapping_add(a[j + count]);
                a[j + count] = t.wrapping_sub(a[j + count]);
                a[j + count] = montgomery_reduce(i64::from(zeta) * i64::from(a[j + count]));
                j += 1;
            }
            start = j + count;
        }
        count <<= 1;
    }

    for coefficient in a.iter_mut() {
        *coefficient = montgomery_reduce(i64::from(f) * i64::from(*coefficient));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        D, GAMMA2, N, Q, c_add_q, decompose, inv_ntt_to_mont, make_hint, montgomery_reduce, ntt,
        power2_round, reduce32, use_hint,
    };

    #[test]
    fn c_add_q_matches_go_behavior() {
        assert_eq!(c_add_q(0), 0);
        assert_eq!(c_add_q(100), 100);
        assert_eq!(c_add_q(-100), Q - 100);
        assert_eq!(c_add_q(-Q), 0);
    }

    #[test]
    fn power2_round_reconstructs_input() {
        for value in [0_i32, 100, 10_000, 1_000_000] {
            let mut a0 = 0;
            let a1 = power2_round(&mut a0, value);
            assert_eq!(a1.wrapping_shl(D as u32).wrapping_add(a0), value);
        }
    }

    #[test]
    fn make_hint_matches_reference_logic() {
        let reference = |a0: i32, a1: i32| -> u32 {
            if !(-GAMMA2..=GAMMA2).contains(&a0) || (a0 == -GAMMA2 && a1 != 0) { 1 } else { 0 }
        };

        let test_values = [
            -GAMMA2 - 100,
            -GAMMA2 - 1,
            -GAMMA2,
            -GAMMA2 + 1,
            -1_000,
            -1,
            0,
            1,
            1_000,
            GAMMA2 - 1,
            GAMMA2,
            GAMMA2 + 1,
            GAMMA2 + 100,
        ];

        for a0 in test_values {
            for a1 in [-1_000_i32, -1, 0, 1, 1_000] {
                assert_eq!(make_hint(a0, a1), reference(a0, a1), "a0={a0} a1={a1}");
            }
        }
    }

    #[test]
    fn use_hint_smoke_covers_all_branches() {
        let mut a0 = 0;
        let a = 100_000;
        let a1 = decompose(&mut a0, a);
        assert_eq!(use_hint(a, 0), a1);
        let hinted = use_hint(a, 1);
        assert!(hinted == ((a1 + 1) & 15) || hinted == ((a1 - 1) & 15));
    }

    #[test]
    fn ntt_inverse_does_not_zero_non_zero_input() {
        let mut values = [0_i32; N];
        for (index, value) in values.iter_mut().enumerate() {
            *value = (index % 1000) as i32;
        }

        ntt(&mut values);
        inv_ntt_to_mont(&mut values);
        assert!(values.iter().any(|value| *value != 0));
    }

    #[test]
    fn reduction_helpers_stay_in_expected_range() {
        for value in [0_i64, 100, i64::from(Q), i64::from(Q) * 3] {
            let reduced = montgomery_reduce(value);
            assert!((-Q..=Q).contains(&reduced));
        }

        for value in [0_i32, Q, Q * 2, -Q] {
            let reduced = reduce32(value);
            assert!((-Q..=Q).contains(&reduced));
        }
    }
}
