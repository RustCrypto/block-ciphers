/*
 * Serpent uses 8 4-bit Sboxes which were designed to be implemented using small
 * circuits. For each block these Sboxes are applied in a bitsliced fashion.
 *
 * For further context see
 *
 * "Serpent: A Proposal for the Advanced Encryption Standard", Anderson, Biham, Knudsen
 * <https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf>
 *
 * The specific Sbox circuits used here were described in
 *
 * "Speeding Up Serpent", Osvik
 * <https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf>
 */

use crate::Words;

pub const fn sbox_e0([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e1([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e2([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e3([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e4([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e5([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e6([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_e7([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d0([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d1([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d2([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d3([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d4([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d5([w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d6([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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

pub const fn sbox_d7([mut w1, mut w2, mut w3, mut w4]: Words) -> Words {
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
