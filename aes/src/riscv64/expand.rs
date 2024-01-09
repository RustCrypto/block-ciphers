use super::{RoundKey, RoundKeys};
use core::{
    arch::riscv64::*,
    mem::{transmute, MaybeUninit},
    ptr::addr_of_mut,
};

// TODO(silvanshade): `WORDS` should be an associated constant once support for that is stable.
pub(super) struct KeyScheduleState<const WORDS: usize, const ROUNDS: usize> {
    data: [u64; WORDS],
    expanded_keys: [MaybeUninit<RoundKey>; ROUNDS],
}

impl KeyScheduleState<2, 11> {
    #[inline(always)]
    fn load(user_key: &[u8; 16]) -> Self {
        let user_key = user_key.as_ptr().cast::<u64>();
        let mut data: [MaybeUninit<u64>; 2] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe { data[0].write(user_key.add(0).read_unaligned()) };
        unsafe { data[1].write(user_key.add(1).read_unaligned()) };
        let mut state = Self {
            data: unsafe { transmute(data) },
            expanded_keys: unsafe { MaybeUninit::uninit().assume_init() },
        };
        state.save_one_keys(0);
        state
    }

    #[inline(always)]
    fn save_one_keys(&mut self, i: u8) {
        let i = usize::from(i);
        let expanded_keys = self.expanded_keys[i].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0]).write(self.data[0]) };
        unsafe { addr_of_mut!((*expanded_keys)[1]).write(self.data[1]) };
    }

    #[inline(always)]
    fn one_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.data[1], RNUM) };
        self.data[0] = unsafe { aes64ks2(s, self.data[0]) };
        self.data[1] = unsafe { aes64ks2(self.data[0], self.data[1]) };
        self.save_one_keys(RNUM + 1)
    }

    #[inline(always)]
    pub(super) fn expand_key(user_key: &[u8; 16]) -> RoundKeys<11> {
        let mut state = Self::load(user_key);
        state.one_key_rounds::<0>();
        state.one_key_rounds::<1>();
        state.one_key_rounds::<2>();
        state.one_key_rounds::<3>();
        state.one_key_rounds::<4>();
        state.one_key_rounds::<5>();
        state.one_key_rounds::<6>();
        state.one_key_rounds::<7>();
        state.one_key_rounds::<8>();
        state.one_key_rounds::<9>();
        unsafe { transmute(state.expanded_keys) }
    }
}

impl KeyScheduleState<3, 13> {
    #[inline(always)]
    fn load(user_key: &[u8; 24]) -> Self {
        let user_key = user_key.as_ptr().cast::<u64>();
        let mut data: [MaybeUninit<u64>; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe { data[0].write(user_key.add(0).read_unaligned()) };
        unsafe { data[1].write(user_key.add(1).read_unaligned()) };
        unsafe { data[2].write(user_key.add(2).read_unaligned()) };
        let mut state = Self {
            data: unsafe { transmute(data) },
            expanded_keys: unsafe { MaybeUninit::uninit().assume_init() },
        };
        state.save_one_and_one_half_keys(0);
        state
    }

    #[inline(always)]
    fn save_one_keys(&mut self, i: u8) {
        let n = usize::from(i) * 3 / 2;
        let k = usize::from(i) % 2;
        let expanded_keys = self.expanded_keys[n + 0].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0 + k]).write(self.data[0]) };
        let expanded_keys = self.expanded_keys[n + k].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[1 - k]).write(self.data[1]) };
    }

    #[inline(always)]
    fn save_one_and_one_half_keys(&mut self, i: u8) {
        let n = usize::from(i) * 3 / 2;
        let k = usize::from(i) % 2;
        let expanded_keys = self.expanded_keys[n + 0].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0 + k]).write(self.data[0]) };
        let expanded_keys = self.expanded_keys[n + k].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[1 - k]).write(self.data[1]) };
        let expanded_keys = self.expanded_keys[n + 1].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0 + k]).write(self.data[2]) };
    }

    #[inline(always)]
    fn one_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.data[2], RNUM) };
        self.data[0] = unsafe { aes64ks2(s, self.data[0]) };
        self.data[1] = unsafe { aes64ks2(self.data[0], self.data[1]) };
        self.save_one_keys(RNUM + 1)
    }

    #[inline(always)]
    fn one_and_one_half_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.data[2], RNUM) };
        self.data[0] = unsafe { aes64ks2(s, self.data[0]) };
        self.data[1] = unsafe { aes64ks2(self.data[0], self.data[1]) };
        self.data[2] = unsafe { aes64ks2(self.data[1], self.data[2]) };
        self.save_one_and_one_half_keys(RNUM + 1)
    }

    #[inline(always)]
    pub(super) fn expand_key(user_key: &[u8; 24]) -> RoundKeys<13> {
        let mut state = Self::load(user_key);
        state.one_and_one_half_key_rounds::<0>();
        state.one_and_one_half_key_rounds::<1>();
        state.one_and_one_half_key_rounds::<2>();
        state.one_and_one_half_key_rounds::<3>();
        state.one_and_one_half_key_rounds::<4>();
        state.one_and_one_half_key_rounds::<5>();
        state.one_and_one_half_key_rounds::<6>();
        state.one_key_rounds::<7>();
        unsafe { transmute(state.expanded_keys) }
    }
}

impl KeyScheduleState<4, 15> {
    #[inline(always)]
    fn load(user_key: &[u8; 32]) -> Self {
        let user_key = user_key.as_ptr().cast::<u64>();
        let mut data: [MaybeUninit<u64>; 4] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe { data[0].write(user_key.add(0).read_unaligned()) };
        unsafe { data[1].write(user_key.add(1).read_unaligned()) };
        unsafe { data[2].write(user_key.add(2).read_unaligned()) };
        unsafe { data[3].write(user_key.add(3).read_unaligned()) };
        let mut state = Self {
            data: unsafe { transmute(data) },
            expanded_keys: unsafe { MaybeUninit::uninit().assume_init() },
        };
        state.save_two_keys(0);
        state
    }

    #[inline(always)]
    fn save_one_keys(&mut self, i: u8) {
        let i = usize::from(i);
        let expanded_keys = self.expanded_keys[2 * i + 0].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0]).write(self.data[0]) };
        unsafe { addr_of_mut!((*expanded_keys)[1]).write(self.data[1]) };
    }

    #[inline(always)]
    fn save_two_keys(&mut self, i: u8) {
        let i = usize::from(i);
        let expanded_keys = self.expanded_keys[2 * i + 0].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0]).write(self.data[0]) };
        unsafe { addr_of_mut!((*expanded_keys)[1]).write(self.data[1]) };
        let expanded_keys = self.expanded_keys[2 * i + 1].as_mut_ptr();
        unsafe { addr_of_mut!((*expanded_keys)[0]).write(self.data[2]) };
        unsafe { addr_of_mut!((*expanded_keys)[1]).write(self.data[3]) };
    }

    #[inline(always)]
    fn two_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.data[3], RNUM) };
        self.data[0] = unsafe { aes64ks2(s, self.data[0]) };
        self.data[1] = unsafe { aes64ks2(self.data[0], self.data[1]) };
        let s = unsafe { aes64ks1i(self.data[1], 0xA) };
        self.data[2] = unsafe { aes64ks2(s, self.data[2]) };
        self.data[3] = unsafe { aes64ks2(self.data[2], self.data[3]) };
        self.save_two_keys(RNUM + 1);
    }

    #[inline(always)]
    fn one_key_rounds<const RNUM: u8>(&mut self) {
        let s = unsafe { aes64ks1i(self.data[3], RNUM) };
        self.data[0] = unsafe { aes64ks2(s, self.data[0]) };
        self.data[1] = unsafe { aes64ks2(self.data[0], self.data[1]) };
        self.save_one_keys(RNUM + 1);
    }

    #[inline(always)]
    pub(super) fn expand_key(user_key: &[u8; 32]) -> RoundKeys<15> {
        let mut state = Self::load(user_key);
        state.two_key_rounds::<0>();
        state.two_key_rounds::<1>();
        state.two_key_rounds::<2>();
        state.two_key_rounds::<3>();
        state.two_key_rounds::<4>();
        state.two_key_rounds::<5>();
        state.one_key_rounds::<6>();
        unsafe { transmute(state.expanded_keys) }
    }
}

#[inline(always)]
pub(super) fn inv_expanded_keys<const N: usize>(keys: &mut RoundKeys<N>) {
    for i in 1..N - 1 {
        keys[i][0] = unsafe { aes64im(keys[i][0]) };
        keys[i][1] = unsafe { aes64im(keys[i][1]) };
    }
}
