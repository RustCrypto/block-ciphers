use super::{BatchBlocks, State, Word, mix_columns::*, sbox::*, utils::*};

/// AES-192 round keys
pub(crate) type RoundKeys<W> = [W; 104];

/// Fully bitsliced AES-192 key schedule to match the fully-fixsliced representation.
pub(crate) fn key_schedule<W: Word>(key: &[u8; 24]) -> RoundKeys<W> {
    let mut rkeys = [W::default(); 104];
    let mut tmp = [W::default(); 8];

    W::bitslice(&mut rkeys[..8], &broadcast::<W>(&key[..16]));
    W::bitslice(&mut tmp, &broadcast::<W>(&key[8..]));

    let mut rcon = 0;
    let mut rk_off = 8;

    loop {
        for i in 0..8 {
            rkeys[rk_off + i] = (W::uniform_row(0x0f) & (tmp[i] >> W::HALF_ROW))
                | (W::uniform_row(0xf0) & (rkeys[(rk_off - 8) + i] << W::HALF_ROW));
        }

        sub_bytes(&mut tmp);
        sub_bytes_nots(&mut tmp);

        add_round_constant_bit(&mut tmp, rcon);
        rcon += 1;

        for i in 0..8 {
            let mut ti = rkeys[rk_off + i];
            ti ^= W::uniform_row(0x30) & tmp[i].ror(W::ror_distance(1, 1));
            ti ^= W::uniform_row(0xc0) & (ti << W::QUARTER_ROW);
            tmp[i] = ti;
        }
        rkeys[rk_off..(rk_off + 8)].copy_from_slice(&tmp);
        rk_off += 8;

        for i in 0..8 {
            let ui = tmp[i];
            let mut ti = (W::uniform_row(0x0f) & (rkeys[(rk_off - 16) + i] >> W::HALF_ROW))
                | (W::uniform_row(0xf0) & (ui << W::HALF_ROW));
            ti ^= W::uniform_row(0x03) & (ui >> (3 * W::QUARTER_ROW));
            tmp[i] = ti
                ^ (W::uniform_row(0xfc) & (ti << W::QUARTER_ROW))
                ^ (W::uniform_row(0xf0) & (ti << W::HALF_ROW))
                ^ (W::uniform_row(0xc0) & (ti << (3 * W::QUARTER_ROW)));
        }
        rkeys[rk_off..(rk_off + 8)].copy_from_slice(&tmp);
        rk_off += 8;

        sub_bytes(&mut tmp);
        sub_bytes_nots(&mut tmp);

        add_round_constant_bit(&mut tmp, rcon);
        rcon += 1;

        for i in 0..8 {
            let mut ti = (W::uniform_row(0x0f) & (rkeys[(rk_off - 16) + i] >> W::HALF_ROW))
                | (W::uniform_row(0xf0) & (rkeys[(rk_off - 8) + i] << W::HALF_ROW));
            ti ^= W::uniform_row(0x03) & tmp[i].ror(W::ror_distance(1, 3));
            rkeys[rk_off + i] = ti
                ^ (W::uniform_row(0xfc) & (ti << W::QUARTER_ROW))
                ^ (W::uniform_row(0xf0) & (ti << W::HALF_ROW))
                ^ (W::uniform_row(0xc0) & (ti << (3 * W::QUARTER_ROW)));
        }
        rk_off += 8;

        if rcon >= 8 {
            break;
        }

        for i in 0..8 {
            let ui = rkeys[(rk_off - 8) + i];
            let mut ti = rkeys[(rk_off - 16) + i];
            ti ^= W::uniform_row(0x30) & (ui >> W::QUARTER_ROW);
            ti ^= W::uniform_row(0xc0) & (ti << W::QUARTER_ROW);
            tmp[i] = ti;
        }
    }

    // Adjust to match fixslicing format
    #[cfg(aes_backend_soft = "compact")]
    {
        for i in (8..104).step_by(16) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        }
    }
    #[cfg(not(aes_backend_soft = "compact"))]
    {
        for i in (0..96).step_by(32) {
            inv_shift_rows_1(&mut rkeys[(i + 8)..(i + 16)]);
            inv_shift_rows_2(&mut rkeys[(i + 16)..(i + 24)]);
            inv_shift_rows_3(&mut rkeys[(i + 24)..(i + 32)]);
        }
    }

    // Account for NOTs removed from sub_bytes
    for i in 1..13 {
        sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully-fixsliced AES-192 encryption (the ShiftRows is completely omitted).
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

        if rk_off == 96 {
            break;
        }

        sub_bytes(&mut state);
        mix_columns_0(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;
    }

    sub_bytes(&mut state);
    add_round_key(&mut state, &rkeys[96..]);

    W::inv_bitslice(&state)
}

/// Fully-fixsliced AES-192 decryption (the InvShiftRows is completely omitted).
///
/// Decrypts four blocks in-place and in parallel.
pub(crate) fn decrypt<W: Word>(rkeys: &RoundKeys<W>, blocks: &BatchBlocks<W>) -> BatchBlocks<W> {
    let mut state = State::<W>::default();

    W::bitslice(&mut state, blocks);

    add_round_key(&mut state, &rkeys[96..]);
    inv_sub_bytes(&mut state);

    let mut rk_off = 88;
    loop {
        #[cfg(aes_backend_soft = "compact")]
        {
            inv_shift_rows_2(&mut state);
        }
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
    }

    add_round_key(&mut state, &rkeys[..8]);

    W::inv_bitslice(&state)
}
