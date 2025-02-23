use crate::{
    Camellia128,
    utils::{gen_subkeys26, set_ka},
};
use cipher::{AlgorithmName, Key, KeyInit};
use core::{fmt, marker::PhantomData};

impl KeyInit for Camellia128 {
    fn new(key: &Key<Self>) -> Self {
        let kl = (
            u64::from_be_bytes(key[0..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
        );
        let kr = (u64::default(), u64::default());

        let ka = set_ka(kl, kr);

        Self {
            k: gen_subkeys26(kl, ka),
            _pd: PhantomData,
        }
    }
}

impl fmt::Debug for Camellia128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Camellia128 { ... }")
    }
}

impl AlgorithmName for Camellia128 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Camellia128")
    }
}
