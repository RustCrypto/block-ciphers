//! Serpent uses 8 4-bit Sboxes which were designed to be implemented using small
//! circuits. For each block these Sboxes are applied in a bitsliced fashion.
//!
//! For further context see
//!
//! "Serpent: A Proposal for the Advanced Encryption Standard", Anderson, Biham, Knudsen
//! <https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf>
//!
//! The specific Sbox circuits used here were described in
//!
//! "Speeding Up Serpent", Osvik
//! <https://www.ii.uib.no/~osvik/pub/aes3.pdf>

use crate::Words;

#[inline]
pub fn linear_transform(mut words: Words) -> Words {
    words[0] = words[0].rotate_left(13);
    words[2] = words[2].rotate_left(3);
    words[1] ^= words[0] ^ words[2];
    words[3] = words[3] ^ words[2] ^ (words[0] << 3);
    words[1] = words[1].rotate_left(1);
    words[3] = words[3].rotate_left(7);
    words[0] ^= words[1] ^ words[3];
    words[2] = words[2] ^ words[3] ^ (words[1] << 7);
    words[0] = words[0].rotate_left(5);
    words[2] = words[2].rotate_left(22);
    words
}

#[inline]
pub fn linear_transform_inv(mut words: Words) -> Words {
    words[2] = words[2].rotate_right(22);
    words[0] = words[0].rotate_right(5);
    words[2] = words[2] ^ words[3] ^ (words[1] << 7);
    words[0] ^= words[1] ^ words[3];
    words[3] = words[3].rotate_right(7);
    words[1] = words[1].rotate_right(1);
    words[3] = words[3] ^ words[2] ^ (words[0] << 3);
    words[1] ^= words[0] ^ words[2];
    words[2] = words[2].rotate_right(3);
    words[0] = words[0].rotate_right(13);
    words
}

#[inline]
pub fn apply_s(index: usize, [w1, w2, w3, w4]: Words) -> Words {
    match index % 8 {
        0 => sbox_e0([w1, w2, w3, w4]),
        1 => sbox_e1([w1, w2, w3, w4]),
        2 => sbox_e2([w1, w2, w3, w4]),
        3 => sbox_e3([w1, w2, w3, w4]),
        4 => sbox_e4([w1, w2, w3, w4]),
        5 => sbox_e5([w1, w2, w3, w4]),
        6 => sbox_e6([w1, w2, w3, w4]),
        7 => sbox_e7([w1, w2, w3, w4]),
        _ => unreachable!(),
    }
}

#[inline]
pub fn apply_s_inv(index: usize, [w1, w2, w3, w4]: Words) -> Words {
    match index % 8 {
        0 => sbox_d0([w1, w2, w3, w4]),
        1 => sbox_d1([w1, w2, w3, w4]),
        2 => sbox_d2([w1, w2, w3, w4]),
        3 => sbox_d3([w1, w2, w3, w4]),
        4 => sbox_d4([w1, w2, w3, w4]),
        5 => sbox_d5([w1, w2, w3, w4]),
        6 => sbox_d6([w1, w2, w3, w4]),
        7 => sbox_d7([w1, w2, w3, w4]),
        _ => unreachable!(),
    }
}

#[inline]
const fn sbox_e0([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w4 ^= w1;
    let mut t0 = w2;
    w2 &= w4;
    t0 ^= w3;
    w2 ^= w1;
    w1 |= w4;
    w1 ^= t0;
    t0 ^= w4;
    w4 ^= w3;
    w3 |= w2;
    w3 ^= t0;
    t0 = !t0;
    t0 |= w2;
    w2 ^= w4;
    w2 ^= t0;
    w4 |= w1;
    w2 ^= w4;
    t0 ^= w4;
    [w2, t0, w3, w1]
}

#[inline]
const fn sbox_e1([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w1 = !w1;
    w3 = !w3;
    let mut t0 = w1;
    w1 &= w2;
    w3 ^= w1;
    w1 |= w4;
    w4 ^= w3;
    w2 ^= w1;
    w1 ^= t0;
    t0 |= w2;
    w2 ^= w4;
    w3 |= w1;
    w3 &= t0;
    w1 ^= w2;
    w2 &= w3;
    w2 ^= w1;
    w1 &= w3;
    t0 ^= w1;
    [w3, t0, w4, w2]
}

#[inline]
const fn sbox_e2([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w1;
    w1 &= w3;
    w1 ^= w4;
    w3 ^= w2;
    w3 ^= w1;
    w4 |= t0;
    w4 ^= w2;
    t0 ^= w3;
    w2 = w4;
    w4 |= t0;
    w4 ^= w1;
    w1 &= w2;
    t0 ^= w1;
    w2 ^= w4;
    w2 ^= t0;
    t0 = !t0;
    [w3, w4, w2, t0]
}

#[inline]
const fn sbox_e3([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w1;
    w1 |= w4;
    w4 ^= w2;
    w2 &= t0;
    t0 ^= w3;
    w3 ^= w4;
    w4 &= w1;
    t0 |= w2;
    w4 ^= t0;
    w1 ^= w2;
    t0 &= w1;
    w2 ^= w4;
    t0 ^= w3;
    w2 |= w1;
    w2 ^= w3;
    w1 ^= w4;
    w3 = w2;
    w2 |= w4;
    w1 ^= w2;
    [w1, w3, w4, t0]
}

#[inline]
const fn sbox_e4([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w2 ^= w4;
    w4 = !w4;
    w3 ^= w4;
    w4 ^= w1;
    let mut t0 = w2;
    w2 &= w4;
    w2 ^= w3;
    t0 ^= w4;
    w1 ^= t0;
    w3 &= t0;
    w3 ^= w1;
    w1 &= w2;
    w4 ^= w1;
    t0 |= w2;
    t0 ^= w1;
    w1 |= w4;
    w1 ^= w3;
    w3 &= w4;
    w1 = !w1;
    t0 ^= w3;
    [w2, t0, w1, w4]
}

#[inline]
const fn sbox_e5([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w1 ^= w2;
    w2 ^= w4;
    w4 = !w4;
    let mut t0 = w2;
    w2 &= w1;
    w3 ^= w4;
    w2 ^= w3;
    w3 |= t0;
    t0 ^= w4;
    w4 &= w2;
    w4 ^= w1;
    t0 ^= w2;
    t0 ^= w3;
    w3 ^= w1;
    w1 &= w4;
    w3 = !w3;
    w1 ^= t0;
    t0 |= w4;
    t0 ^= w3;
    w3 = w1;
    w1 = w2;
    w2 = w4;
    w4 = t0;
    [w1, w2, w3, w4]
}

#[inline]
const fn sbox_e6([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w3 = !w3;
    let mut t0 = w4;
    w4 &= w1;
    w1 ^= t0;
    w4 ^= w3;
    w3 |= t0;
    w2 ^= w4;
    w3 ^= w1;
    w1 |= w2;
    w3 ^= w2;
    t0 ^= w1;
    w1 |= w4;
    w1 ^= w3;
    t0 ^= w4;
    t0 ^= w1;
    w4 = !w4;
    w3 &= t0;
    w4 ^= w3;
    w3 = t0;
    [w1, w2, w3, w4]
}

#[inline]
const fn sbox_e7([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w2;
    w2 |= w3;
    w2 ^= w4;
    t0 ^= w3;
    w3 ^= w2;
    w4 |= t0;
    w4 &= w1;
    t0 ^= w3;
    w4 ^= w2;
    w2 |= t0;
    w2 ^= w1;
    w1 |= t0;
    w1 ^= w3;
    w2 ^= t0;
    w3 ^= w2;
    w2 &= w1;
    w2 ^= t0;
    w3 = !w3;
    w3 |= w1;
    t0 ^= w3;
    [t0, w4, w2, w1]
}

#[inline]
const fn sbox_d0([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w3 = !w3;
    let mut t0 = w2;
    w2 |= w1;
    t0 = !t0;
    w2 ^= w3;
    w3 |= t0;
    w2 ^= w4;
    w1 ^= t0;
    w3 ^= w1;
    w1 &= w4;
    t0 ^= w1;
    w1 |= w2;
    w1 ^= w3;
    w4 ^= t0;
    w3 ^= w2;
    w4 ^= w1;
    w4 ^= w2;
    w3 &= w4;
    t0 ^= w3;
    [w1, t0, w2, w4]
}

#[inline]
const fn sbox_d1([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w2;
    w2 ^= w4;
    w4 &= w2;
    t0 ^= w3;
    w4 ^= w1;
    w1 |= w2;
    w3 ^= w4;
    w1 ^= t0;
    w1 |= w3;
    w2 ^= w4;
    w1 ^= w2;
    w2 |= w4;
    w2 ^= w1;
    t0 = !t0;
    t0 ^= w2;
    w2 |= w1;
    w2 ^= w1;
    w2 |= t0;
    w4 ^= w2;
    [t0, w1, w4, w3]
}

#[inline]
const fn sbox_d2([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w3 ^= w4;
    w4 ^= w1;
    let mut t0 = w4;
    w4 &= w3;
    w4 ^= w2;
    w2 |= w3;
    w2 ^= t0;
    t0 &= w4;
    w3 ^= w4;
    t0 &= w1;
    t0 ^= w3;
    w3 &= w2;
    w3 |= w1;
    w4 = !w4;
    w3 ^= w4;
    w1 ^= w4;
    w1 &= w2;
    w4 ^= t0;
    w4 ^= w1;
    [w2, t0, w3, w4]
}

#[inline]
const fn sbox_d3([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w3;
    w3 ^= w2;
    w1 ^= w3;
    t0 &= w3;
    t0 ^= w1;
    w1 &= w2;
    w2 ^= w4;
    w4 |= t0;
    w3 ^= w4;
    w1 ^= w4;
    w2 ^= t0;
    w4 &= w3;
    w4 ^= w2;
    w2 ^= w1;
    w2 |= w3;
    w1 ^= w4;
    w2 ^= t0;
    w1 ^= w2;
    [w3, w2, w4, w1]
}

#[inline]
const fn sbox_d4([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w3;
    w3 &= w4;
    w3 ^= w2;
    w2 |= w4;
    w2 &= w1;
    t0 ^= w3;
    t0 ^= w2;
    w2 &= w3;
    w1 = !w1;
    w4 ^= t0;
    w2 ^= w4;
    w4 &= w1;
    w4 ^= w3;
    w1 ^= w2;
    w3 &= w1;
    w4 ^= w1;
    w3 ^= t0;
    w3 |= w4;
    w4 ^= w1;
    w3 ^= w2;
    [w1, w4, w3, t0]
}

#[inline]
const fn sbox_d5([w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w2 = !w2;
    let mut t0 = w4;
    w3 ^= w2;
    w4 |= w1;
    w4 ^= w3;
    w3 |= w2;
    w3 &= w1;
    t0 ^= w4;
    w3 ^= t0;
    t0 |= w1;
    t0 ^= w2;
    w2 &= w3;
    w2 ^= w4;
    t0 ^= w3;
    w4 &= t0;
    t0 ^= w2;
    w4 ^= t0;
    t0 = !t0;
    w4 ^= w1;
    [w2, t0, w4, w3]
}

#[inline]
const fn sbox_d6([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    w1 ^= w3;
    let mut t0 = w3;
    w3 &= w1;
    t0 ^= w4;
    w3 = !w3;
    w4 ^= w2;
    w3 ^= w4;
    t0 |= w1;
    w1 ^= w3;
    w4 ^= t0;
    t0 ^= w2;
    w2 &= w4;
    w2 ^= w1;
    w1 ^= w4;
    w1 |= w3;
    w4 ^= w2;
    t0 ^= w1;
    [w2, w3, t0, w4]
}

#[inline]
const fn sbox_d7([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
    let mut t0 = w3;
    w3 ^= w1;
    w1 &= w4;
    t0 |= w4;
    w3 = !w3;
    w4 ^= w2;
    w2 |= w1;
    w1 ^= w3;
    w3 &= t0;
    w4 &= t0;
    w2 ^= w3;
    w3 ^= w1;
    w1 |= w3;
    t0 ^= w2;
    w1 ^= w4;
    w4 ^= t0;
    t0 |= w1;
    w4 ^= w3;
    t0 ^= w3;
    [w4, w1, w2, t0]
}
