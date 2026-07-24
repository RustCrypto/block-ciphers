use super::{State, Word};

/// Computation of the MixColumns transformation in the fixsliced representation,
/// with different rotations used according to the round number mod 4.
///
/// Based on Käsper-Schwabe, similar to https://github.com/Ko-/aes-armcortexm.
macro_rules! define_mix_columns {
    (
        $name:ident,
        $name_inv:ident,
        $first_rotate:path,
        $second_rotate:path
    ) => {
        #[rustfmt::skip]
        pub(super) fn $name<W: Word>(state: &mut State<W>) {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = (
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
            );
            let (b0, b1, b2, b3, b4, b5, b6, b7) = (
                $first_rotate(a0),
                $first_rotate(a1),
                $first_rotate(a2),
                $first_rotate(a3),
                $first_rotate(a4),
                $first_rotate(a5),
                $first_rotate(a6),
                $first_rotate(a7),
            );
            let (c0, c1, c2, c3, c4, c5, c6, c7) = (
                a0 ^ b0,
                a1 ^ b1,
                a2 ^ b2,
                a3 ^ b3,
                a4 ^ b4,
                a5 ^ b5,
                a6 ^ b6,
                a7 ^ b7,
            );
            state[0] = b0      ^ c7 ^ $second_rotate(c0);
            state[1] = b1 ^ c0 ^ c7 ^ $second_rotate(c1);
            state[2] = b2 ^ c1      ^ $second_rotate(c2);
            state[3] = b3 ^ c2 ^ c7 ^ $second_rotate(c3);
            state[4] = b4 ^ c3 ^ c7 ^ $second_rotate(c4);
            state[5] = b5 ^ c4      ^ $second_rotate(c5);
            state[6] = b6 ^ c5      ^ $second_rotate(c6);
            state[7] = b7 ^ c6      ^ $second_rotate(c7);
        }

        #[rustfmt::skip]
        pub(super) fn $name_inv<W: Word>(state: &mut State<W>) {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = (
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
            );
            let (b0, b1, b2, b3, b4, b5, b6, b7) = (
                $first_rotate(a0),
                $first_rotate(a1),
                $first_rotate(a2),
                $first_rotate(a3),
                $first_rotate(a4),
                $first_rotate(a5),
                $first_rotate(a6),
                $first_rotate(a7),
            );
            let (c0, c1, c2, c3, c4, c5, c6, c7) = (
                a0 ^ b0,
                a1 ^ b1,
                a2 ^ b2,
                a3 ^ b3,
                a4 ^ b4,
                a5 ^ b5,
                a6 ^ b6,
                a7 ^ b7,
            );
            let (d0, d1, d2, d3, d4, d5, d6, d7) = (
                a0      ^ c7,
                a1 ^ c0 ^ c7,
                a2 ^ c1,
                a3 ^ c2 ^ c7,
                a4 ^ c3 ^ c7,
                a5 ^ c4,
                a6 ^ c5,
                a7 ^ c6,
            );
            let (e0, e1, e2, e3, e4, e5, e6, e7) = (
                c0      ^ d6,
                c1      ^ d6 ^ d7,
                c2 ^ d0      ^ d7,
                c3 ^ d1 ^ d6,
                c4 ^ d2 ^ d6 ^ d7,
                c5 ^ d3      ^ d7,
                c6 ^ d4,
                c7 ^ d5,
            );
            state[0] = d0 ^ e0 ^ $second_rotate(e0);
            state[1] = d1 ^ e1 ^ $second_rotate(e1);
            state[2] = d2 ^ e2 ^ $second_rotate(e2);
            state[3] = d3 ^ e3 ^ $second_rotate(e3);
            state[4] = d4 ^ e4 ^ $second_rotate(e4);
            state[5] = d5 ^ e5 ^ $second_rotate(e5);
            state[6] = d6 ^ e6 ^ $second_rotate(e6);
            state[7] = d7 ^ e7 ^ $second_rotate(e7);
        }
    };
}

define_mix_columns!(
    mix_columns_0,
    inv_mix_columns_0,
    rotate_rows_1,
    rotate_rows_2
);

define_mix_columns!(
    mix_columns_1,
    inv_mix_columns_1,
    rotate_rows_and_columns_1_1,
    rotate_rows_and_columns_2_2
);

#[cfg(not(aes_backend_soft = "compact"))]
define_mix_columns!(
    mix_columns_2,
    inv_mix_columns_2,
    rotate_rows_and_columns_1_2,
    rotate_rows_2
);

#[cfg(not(aes_backend_soft = "compact"))]
define_mix_columns!(
    mix_columns_3,
    inv_mix_columns_3,
    rotate_rows_and_columns_1_3,
    rotate_rows_and_columns_2_2
);

#[inline(always)]
fn rotate_rows_1<W: Word>(x: W) -> W {
    x.ror(W::ror_distance(1, 0))
}

#[inline(always)]
fn rotate_rows_2<W: Word>(x: W) -> W {
    x.ror(W::ror_distance(2, 0))
}

#[inline(always)]
fn rotate_rows_and_columns_1_1<W: Word>(x: W) -> W {
    let a = x.ror(W::ror_distance(1, 1)) & W::uniform_row(0x3f);
    let b = x.ror(W::ror_distance(0, 1)) & W::uniform_row(0xc0);
    a | b
}

#[cfg(not(aes_backend_soft = "compact"))]
#[inline(always)]
fn rotate_rows_and_columns_1_2<W: Word>(x: W) -> W {
    let a = x.ror(W::ror_distance(1, 2)) & W::uniform_row(0x0f);
    let b = x.ror(W::ror_distance(0, 2)) & W::uniform_row(0xf0);
    a | b
}

#[cfg(not(aes_backend_soft = "compact"))]
#[inline(always)]
fn rotate_rows_and_columns_1_3<W: Word>(x: W) -> W {
    let a = x.ror(W::ror_distance(1, 3)) & W::uniform_row(0x03);
    let b = x.ror(W::ror_distance(0, 3)) & W::uniform_row(0xfc);
    a | b
}

#[inline(always)]
fn rotate_rows_and_columns_2_2<W: Word>(x: W) -> W {
    let a = x.ror(W::ror_distance(2, 2)) & W::uniform_row(0x0f);
    let b = x.ror(W::ror_distance(1, 2)) & W::uniform_row(0xf0);
    a | b
}
