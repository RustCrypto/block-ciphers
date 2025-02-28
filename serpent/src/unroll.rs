#[cfg(not(serpent_no_unroll))]
#[rustfmt::skip]
macro_rules! unroll31 {
    ($i:ident, $body:block) => {
        let $i = 0; $body;
        let $i = 1; $body;
        let $i = 2; $body;
        let $i = 3; $body;
        let $i = 4; $body;
        let $i = 5; $body;
        let $i = 6; $body;
        let $i = 7; $body;
        let $i = 8; $body;
        let $i = 9; $body;
        let $i = 10; $body;
        let $i = 11; $body;
        let $i = 12; $body;
        let $i = 13; $body;
        let $i = 14; $body;
        let $i = 15; $body;
        let $i = 16; $body;
        let $i = 17; $body;
        let $i = 18; $body;
        let $i = 19; $body;
        let $i = 20; $body;
        let $i = 21; $body;
        let $i = 22; $body;
        let $i = 23; $body;
        let $i = 24; $body;
        let $i = 25; $body;
        let $i = 26; $body;
        let $i = 27; $body;
        let $i = 28; $body;
        let $i = 29; $body;
        let $i = 30; $body;
    };
}

#[cfg(serpent_no_unroll)]
macro_rules! unroll31 {
    ($i:ident, $body:block) => {
        for $i in 0..31 {
            $body;
        }
    };
}
