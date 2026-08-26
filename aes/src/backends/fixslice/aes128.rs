use super::{BatchBlocks, State, Word, mix_columns::*, sbox::*, utils::*};

/// AES-128 round keys
pub(crate) type RoundKeys<W> = [W; 88];

/// Fully bitsliced AES-128 key schedule to match the fully-fixsliced representation.
pub(crate) fn key_schedule<W: Word>(key: &[u8; 16]) -> RoundKeys<W> {
    let mut rkeys = [W::default(); 88];

    W::bitslice(&mut rkeys[..8], &broadcast::<W>(key));

    let mut rk_off = 0;
    for rcon in 0..10 {
        memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        if rcon < 8 {
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon);
        } else {
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 8);
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 7);
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 5);
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 4);
        }

        xor_columns(&mut rkeys, rk_off, 8, W::ror_distance(1, 3));
    }

    // Adjust to match fixslicing format
    #[cfg(aes_backend_soft = "compact")]
    {
        for i in (8..88).step_by(16) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        }
    }
    #[cfg(not(aes_backend_soft = "compact"))]
    {
        for i in (8..72).step_by(32) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
            inv_shift_rows_2(&mut rkeys[(i + 8)..(i + 16)]);
            inv_shift_rows_3(&mut rkeys[(i + 16)..(i + 24)]);
        }
        inv_shift_rows_1(&mut rkeys[72..80]);
    }

    // Account for NOTs removed from sub_bytes
    for i in 1..11 {
        sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully-fixsliced AES-128 encryption (the ShiftRows is completely omitted).
///
/// Encrypts four blocks in-place and in parallel.
pub(crate) fn encrypt<W: Word>(rkeys: &RoundKeys<W>, blocks: &BatchBlocks<W>) -> BatchBlocks<W> {
    let mut state = State::<W>::default();

    W::bitslice(&mut state, blocks);

    add_round_key(&mut state, &rkeys[..8]);

    let mut rk_off = 8;
    loop {
        sub_bytes(&mut state);
        mix_columns_1(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        #[cfg(aes_backend_soft = "compact")]
        {
            shift_rows_2(&mut state);
        }

        if rk_off == 80 {
            break;
        }

        #[cfg(not(aes_backend_soft = "compact"))]
        {
            sub_bytes(&mut state);
            mix_columns_2(&mut state);
            add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
            rk_off += 8;

            sub_bytes(&mut state);
            mix_columns_3(&mut state);
            add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
            rk_off += 8;
        }

        sub_bytes(&mut state);
        mix_columns_0(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;
    }

    #[cfg(not(aes_backend_soft = "compact"))]
    {
        shift_rows_2(&mut state);
    }

    sub_bytes(&mut state);
    add_round_key(&mut state, &rkeys[80..]);

    W::inv_bitslice(&state)
}

/// Fully-fixsliced AES-128 decryption (the InvShiftRows is completely omitted).
///
/// Decrypts four blocks in-place and in parallel.
pub(crate) fn decrypt<W: Word>(rkeys: &RoundKeys<W>, blocks: &BatchBlocks<W>) -> BatchBlocks<W> {
    let mut state = State::<W>::default();

    W::bitslice(&mut state, blocks);

    add_round_key(&mut state, &rkeys[80..]);
    inv_sub_bytes(&mut state);

    #[cfg(not(aes_backend_soft = "compact"))]
    {
        inv_shift_rows_2(&mut state);
    }

    let mut rk_off = 72;
    loop {
        #[cfg(aes_backend_soft = "compact")]
        {
            inv_shift_rows_2(&mut state);
        }

        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        inv_mix_columns_1(&mut state);
        inv_sub_bytes(&mut state);
        rk_off -= 8;

        if rk_off == 0 {
            break;
        }

        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        inv_mix_columns_0(&mut state);
        inv_sub_bytes(&mut state);
        rk_off -= 8;

        #[cfg(not(aes_backend_soft = "compact"))]
        {
            add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
            inv_mix_columns_3(&mut state);
            inv_sub_bytes(&mut state);
            rk_off -= 8;

            add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
            inv_mix_columns_2(&mut state);
            inv_sub_bytes(&mut state);
            rk_off -= 8;
        }
    }

    add_round_key(&mut state, &rkeys[..8]);

    W::inv_bitslice(&state)
}
