#![allow(clippy::identity_op)]

use crate::riscv::rv64::{RoundKey, RoundKeys};
use core::{arch::riscv64::*, mem::MaybeUninit};

// TODO(silvanshade): `COLUMNS` should be an associated constant once support for that is stable.
pub(crate) struct KeySchedule<const COLUMNS: usize, const ROUNDS: usize> {
    cols: [u64; COLUMNS],
    keys: [MaybeUninit<RoundKey>; ROUNDS],
}

// AES-128: COLUMNS: 4 x 32-bit words = 2 x 64-bit words
impl KeySchedule<{ 4 / 2 }, { 1 + 10 }> {
    #[inline(always)]
    fn load(ckey: &[u8; 16]) -> Self {
        let ckey = ckey.as_ptr().cast::<u64>();
        let mut cols: [MaybeUninit<u64>; 2] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe { cols[0].write(ckey.add(0).read_unaligned()) };
        unsafe { cols[1].write(ckey.add(1).read_unaligned()) };
        #[allow(clippy::missing_transmute_annotations)]
        let mut schedule = Self {
            // SAFETY: `data` is fully initialized.
            cols: unsafe { ::core::mem::transmute(cols) },
            keys: unsafe { MaybeUninit::uninit().assume_init() },
        };
        schedule.save_one_keys(0);
        schedule
    }

    #[inline(always)]
    fn save_one_keys(&mut self, i: u8) {
        let i = usize::from(i);
        let keys = self.keys[i].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0).write(self.cols[0]) };
        unsafe { keys.add(1).write(self.cols[1]) };
    }

    #[inline(always)]
    fn one_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.cols[1], RNUM) };
        self.cols[0] = unsafe { aes64ks2(s, self.cols[0]) };
        self.cols[1] = unsafe { aes64ks2(self.cols[0], self.cols[1]) };
        self.save_one_keys(RNUM + 1)
    }

    #[inline(always)]
    pub(crate) fn expand_key(ckey: &[u8; 16]) -> RoundKeys<11> {
        let mut schedule = Self::load(ckey);
        schedule.one_key_rounds::<0>();
        schedule.one_key_rounds::<1>();
        schedule.one_key_rounds::<2>();
        schedule.one_key_rounds::<3>();
        schedule.one_key_rounds::<4>();
        schedule.one_key_rounds::<5>();
        schedule.one_key_rounds::<6>();
        schedule.one_key_rounds::<7>();
        schedule.one_key_rounds::<8>();
        schedule.one_key_rounds::<9>();
        // SAFETY: `state.expanded_keys` is fully initialized.
        unsafe { ::core::mem::transmute(schedule.keys) }
    }
}

// AES-192: COLUMNS: 6 x 32-bit words = 3 x 64-bit words
impl KeySchedule<{ 6 / 2 }, { 1 + 12 }> {
    #[inline(always)]
    fn load(ckey: &[u8; 24]) -> Self {
        let ckey = ckey.as_ptr().cast::<u64>();
        let mut cols: [MaybeUninit<u64>; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe { cols[0].write(ckey.add(0).read_unaligned()) };
        unsafe { cols[1].write(ckey.add(1).read_unaligned()) };
        unsafe { cols[2].write(ckey.add(2).read_unaligned()) };
        #[allow(clippy::missing_transmute_annotations)]
        let mut schedule = Self {
            // SAFETY: `data` is fully initialized.
            cols: unsafe { ::core::mem::transmute(cols) },
            keys: unsafe { MaybeUninit::uninit().assume_init() },
        };
        schedule.save_one_and_one_half_keys(0);
        schedule
    }

    #[inline(always)]
    fn save_one_keys(&mut self, i: u8) {
        let n = usize::from(i) * 3 / 2;
        let k = usize::from(i) % 2;
        let keys = self.keys[n + 0].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0 + k).write(self.cols[0]) };
        let keys = self.keys[n + k].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(1 - k).write(self.cols[1]) };
    }

    #[inline(always)]
    fn save_one_and_one_half_keys(&mut self, i: u8) {
        let n = usize::from(i) * 3 / 2;
        let k = usize::from(i) % 2;
        let keys = self.keys[n + 0].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0 + k).write(self.cols[0]) };
        let keys = self.keys[n + k].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(1 - k).write(self.cols[1]) };
        let keys = self.keys[n + 1].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0 + k).write(self.cols[2]) };
    }

    #[inline(always)]
    fn one_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.cols[2], RNUM) };
        self.cols[0] = unsafe { aes64ks2(s, self.cols[0]) };
        self.cols[1] = unsafe { aes64ks2(self.cols[0], self.cols[1]) };
        self.save_one_keys(RNUM + 1)
    }

    #[inline(always)]
    fn one_and_one_half_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.cols[2], RNUM) };
        self.cols[0] = unsafe { aes64ks2(s, self.cols[0]) };
        self.cols[1] = unsafe { aes64ks2(self.cols[0], self.cols[1]) };
        self.cols[2] = unsafe { aes64ks2(self.cols[1], self.cols[2]) };
        self.save_one_and_one_half_keys(RNUM + 1)
    }

    #[inline(always)]
    pub(crate) fn expand_key(ckey: &[u8; 24]) -> RoundKeys<13> {
        let mut schedule = Self::load(ckey);
        schedule.one_and_one_half_key_rounds::<0>();
        schedule.one_and_one_half_key_rounds::<1>();
        schedule.one_and_one_half_key_rounds::<2>();
        schedule.one_and_one_half_key_rounds::<3>();
        schedule.one_and_one_half_key_rounds::<4>();
        schedule.one_and_one_half_key_rounds::<5>();
        schedule.one_and_one_half_key_rounds::<6>();
        schedule.one_key_rounds::<7>();
        // SAFETY: `state.expanded_keys` is fully initialized.
        unsafe { ::core::mem::transmute(schedule.keys) }
    }
}

// AES-256: COLUMNS: 8 x 32-bit words = 4 x 64-bit words
impl KeySchedule<{ 8 / 2 }, { 1 + 14 }> {
    #[inline(always)]
    fn load(ckey: &[u8; 32]) -> Self {
        let ckey = ckey.as_ptr().cast::<u64>();
        let mut cols: [MaybeUninit<u64>; 4] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe { cols[0].write(ckey.add(0).read_unaligned()) };
        unsafe { cols[1].write(ckey.add(1).read_unaligned()) };
        unsafe { cols[2].write(ckey.add(2).read_unaligned()) };
        unsafe { cols[3].write(ckey.add(3).read_unaligned()) };
        #[allow(clippy::missing_transmute_annotations)]
        let mut schedule = Self {
            // SAFETY: `data` is fully initialized.
            cols: unsafe { ::core::mem::transmute(cols) },
            keys: unsafe { MaybeUninit::uninit().assume_init() },
        };
        schedule.save_two_keys(0);
        schedule
    }

    #[inline(always)]
    fn save_one_keys(&mut self, i: u8) {
        let i = usize::from(i);
        let keys = self.keys[2 * i + 0].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0).write(self.cols[0]) };
        unsafe { keys.add(1).write(self.cols[1]) };
    }

    #[inline(always)]
    fn save_two_keys(&mut self, i: u8) {
        let i = usize::from(i);
        let keys = self.keys[2 * i + 0].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0).write(self.cols[0]) };
        unsafe { keys.add(1).write(self.cols[1]) };
        let keys = self.keys[2 * i + 1].as_mut_ptr().cast::<u64>();
        unsafe { keys.add(0).write(self.cols[2]) };
        unsafe { keys.add(1).write(self.cols[3]) };
    }

    #[inline(always)]
    fn two_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.cols[3], RNUM) };
        self.cols[0] = unsafe { aes64ks2(s, self.cols[0]) };
        self.cols[1] = unsafe { aes64ks2(self.cols[0], self.cols[1]) };
        let s = unsafe { aes64ks1i(self.cols[1], 0xA) };
        self.cols[2] = unsafe { aes64ks2(s, self.cols[2]) };
        self.cols[3] = unsafe { aes64ks2(self.cols[2], self.cols[3]) };
        self.save_two_keys(RNUM + 1);
    }

    #[inline(always)]
    fn one_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.cols[3], RNUM) };
        self.cols[0] = unsafe { aes64ks2(s, self.cols[0]) };
        self.cols[1] = unsafe { aes64ks2(self.cols[0], self.cols[1]) };
        self.save_one_keys(RNUM + 1);
    }

    #[inline(always)]
    pub(crate) fn expand_key(user_key: &[u8; 32]) -> RoundKeys<15> {
        let mut schedule = Self::load(user_key);
        schedule.two_key_rounds::<0>();
        schedule.two_key_rounds::<1>();
        schedule.two_key_rounds::<2>();
        schedule.two_key_rounds::<3>();
        schedule.two_key_rounds::<4>();
        schedule.two_key_rounds::<5>();
        schedule.one_key_rounds::<6>();
        // SAFETY: `state.expanded_keys` is fully initialized.
        unsafe { ::core::mem::transmute(schedule.keys) }
    }
}

#[inline(always)]
pub fn inv_expanded_keys<const N: usize>(keys: &mut RoundKeys<N>) {
    (1..N - 1).for_each(|i| {
        keys[i][0] = unsafe { aes64im(keys[i][0]) };
        keys[i][1] = unsafe { aes64im(keys[i][1]) };
    });
}
