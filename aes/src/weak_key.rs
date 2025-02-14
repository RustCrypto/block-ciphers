pub(crate) fn test192(key: &[u8; 24]) -> Result<(), WeakKeyError> {
    let t1 = u32::from_ne_bytes(key[..4].try_into().unwrap());
    let t2 = u32::from_ne_bytes(key[4..8].try_into().unwrap());
    let t3 = u32::from_ne_bytes(key[8..12].try_into().unwrap());
    match t1 | t2 | t3 {
        0 => Err(WeakKeyError),
        _ => Ok(()),
    }
}

pub(crate) fn test256(key: &[u8; 32]) -> Result<(), WeakKeyError> {
    let t = u128::from_ne_bytes(key[..16].try_into().unwrap());
    match t {
        0 => Err(WeakKeyError),
        _ => Ok(()),
    }
}
