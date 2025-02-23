use crate::{
    Aria192,
    consts::{C1, C2, C3},
    utils::{a, fe, fo},
};
use cipher::{AlgorithmName, Key, KeyInit, KeySizeUser, consts::U24};
use core::fmt;

impl KeySizeUser for Aria192 {
    type KeySize = U24;
}

impl KeyInit for Aria192 {
    fn new(key: &Key<Self>) -> Self {
        let kl = u128::from_be_bytes(key[0..16].try_into().unwrap());
        let kr = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let kr = (kr as u128) << 64;

        let w0 = kl;
        let w1 = fo(w0 ^ C2) ^ kr;
        let w2 = fe(w1 ^ C3) ^ w0;
        let w3 = fo(w2 ^ C1) ^ w1;

        let ek = [
            w0 ^ w1.rotate_right(19),
            w1 ^ w2.rotate_right(19),
            w2 ^ w3.rotate_right(19),
            w3 ^ w0.rotate_right(19),
            w0 ^ w1.rotate_right(31),
            w1 ^ w2.rotate_right(31),
            w2 ^ w3.rotate_right(31),
            w3 ^ w0.rotate_right(31),
            w0 ^ w1.rotate_left(61),
            w1 ^ w2.rotate_left(61),
            w2 ^ w3.rotate_left(61),
            w3 ^ w0.rotate_left(61),
            w0 ^ w1.rotate_left(31),
            w1 ^ w2.rotate_left(31),
            w2 ^ w3.rotate_left(31),
        ];

        let dk = [
            ek[14],
            a(ek[13]),
            a(ek[12]),
            a(ek[11]),
            a(ek[10]),
            a(ek[9]),
            a(ek[8]),
            a(ek[7]),
            a(ek[6]),
            a(ek[5]),
            a(ek[4]),
            a(ek[3]),
            a(ek[2]),
            a(ek[1]),
            ek[0],
        ];

        Self { ek, dk }
    }
}

impl fmt::Debug for Aria192 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aria192 { ... }")
    }
}

impl AlgorithmName for Aria192 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aria192")
    }
}
