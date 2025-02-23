use crate::{
    Camellia256,
    utils::{get_subkeys34, set_ka, set_kb},
};
use cipher::{AlgorithmName, Key, KeyInit};
use core::{fmt, marker::PhantomData};

impl KeyInit for Camellia256 {
    fn new(key: &Key<Self>) -> Self {
        let kl = (
            u64::from_be_bytes(key[0..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
        );
        let kr = (
            u64::from_be_bytes(key[16..24].try_into().unwrap()),
            u64::from_be_bytes(key[24..32].try_into().unwrap()),
        );

        let ka = set_ka(kl, kr);
        let kb = set_kb(ka, kr);

        Self {
            k: get_subkeys34(kl, kr, ka, kb),
            _pd: PhantomData,
        }
    }
}

impl fmt::Debug for Camellia256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Camellia256 { ... }")
    }
}

impl AlgorithmName for Camellia256 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Camellia256")
    }
}
