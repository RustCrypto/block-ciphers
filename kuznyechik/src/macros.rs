#![cfg_attr(rustfmt, rustfmt_skip)]

#[cfg(not(feature = "no_unroll"))]
#[rustfmt::skip]
macro_rules! unroll9 {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
        { let $var: usize = 3; $body; }
        { let $var: usize = 4; $body; }
        { let $var: usize = 5; $body; }
        { let $var: usize = 6; $body; }
        { let $var: usize = 7; $body; }
        { let $var: usize = 8; $body; }
    };
}

#[cfg(feature = "no_unroll")]
macro_rules! unroll9 {
    ($var:ident, $body:block) => {
        for $var in 0..9 $body
    }
}

#[cfg(not(feature = "no_unroll"))]
#[rustfmt::skip]
macro_rules! unroll16 {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
        { let $var: usize = 3; $body; }
        { let $var: usize = 4; $body; }
        { let $var: usize = 5; $body; }
        { let $var: usize = 6; $body; }
        { let $var: usize = 7; $body; }
        { let $var: usize = 8; $body; }
        { let $var: usize = 9; $body; }
        { let $var: usize = 10; $body; }
        { let $var: usize = 11; $body; }
        { let $var: usize = 12; $body; }
        { let $var: usize = 13; $body; }
        { let $var: usize = 14; $body; }
        { let $var: usize = 15; $body; }
    };
}

#[cfg(feature = "no_unroll")]
macro_rules! unroll16 {
    ($var:ident, $body:block) => {
        for $var in 0..16 $body
    }
}
