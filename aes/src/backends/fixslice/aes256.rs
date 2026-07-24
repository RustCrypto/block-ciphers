use super::{BatchBlocks, State, Word, mix_columns::*, sbox::*, utils::*};

/// AES-256 round keys
pub(crate) type RoundKeys<W> = [W; 120];

/// Fully bitsliced AES-256 key schedule to match the fully-fixsliced representation.
pub(crate) fn key_schedule<W: Word>(key: &[u8; 32]) -> RoundKeys<W> {
    let mut rkeys = [W::default(); 120];

    W::bitslice(&mut rkeys[..8], &broadcast::<W>(&key[..16]));
    W::bitslice(&mut rkeys[8..16], &broadcast::<W>(&key[16..]));

    let mut rk_off = 8;

    let mut rcon = 0;
    loop {
        memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon);
        xor_columns(&mut rkeys, rk_off, 16, W::ror_distance(1, 3));
        rcon += 1;

        if rcon == 7 {
            break;
        }

        memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        xor_columns(&mut rkeys, rk_off, 16, W::ror_distance(0, 3));
    }

    // Adjust to match fixslicing format
    #[cfg(aes_backend_soft = "compact")]
    {
        for i in (8..120).step_by(16) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        }
    }
    #[cfg(not(aes_backend_soft = "compact"))]
    {
        for i in (8..104).step_by(32) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
            inv_shift_rows_2(&mut rkeys[(i + 8)..(i + 16)]);
            inv_shift_rows_3(&mut rkeys[(i + 16)..(i + 24)]);
        }
        inv_shift_rows_1(&mut rkeys[104..112]);
    }

    // Account for NOTs removed from sub_bytes
    for i in 1..15 {
        sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully-fixsliced AES-256 encryption (the ShiftRows is completely omitted).
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

        if rk_off == 112 {
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
    add_round_key(&mut state, &rkeys[112..]);

    W::inv_bitslice(&state)
}

/// Fully-fixsliced AES-256 decryption (the InvShiftRows is completely omitted).
///
/// Decrypts four blocks in-place and in parallel.
pub(crate) fn decrypt<W: Word>(rkeys: &RoundKeys<W>, blocks: &BatchBlocks<W>) -> BatchBlocks<W> {
    let mut state = State::<W>::default();

    W::bitslice(&mut state, blocks);

    add_round_key(&mut state, &rkeys[112..]);
    inv_sub_bytes(&mut state);

    #[cfg(not(aes_backend_soft = "compact"))]
    {
        inv_shift_rows_2(&mut state);
    }

    let mut rk_off = 104;
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
