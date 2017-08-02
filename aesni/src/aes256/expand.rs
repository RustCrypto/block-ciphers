use u64x2::u64x2;

macro_rules! expand_main {
    ($round:expr, $enc_keys:ident, $pos:expr) => {
        asm!(concat!(
            "aeskeygenassist xmm2, xmm3, ", $round,
            "
            pshufd xmm2, xmm2, 0xff

            movdqa xmm4, xmm1
            pslldq xmm4, 0x4
            pxor xmm1, xmm4

            pslldq xmm4, 0x4
            pxor xmm1, xmm4

            pslldq xmm4, 0x4
            pxor xmm1, xmm4

            pxor xmm1, xmm2
            ")
            : "={xmm1}"($enc_keys[$pos])
            : "{xmm3}"($enc_keys[$pos-1]), "{xmm1}"($enc_keys[$pos-2])
            : "xmm2", "xmm4"
            : "intel", "alignstack", "volatile"
        );
    }
}

macro_rules! expand_round_last {
    ($round:expr, $enc_keys:ident, $dec_keys:ident, $pos:expr) => {
        expand_main!($round, $enc_keys, $pos);
        $dec_keys[$pos] = $enc_keys[$pos];
    }
}

macro_rules! expand_round {
    ($round:expr, $enc_keys:ident, $dec_keys:ident, $pos:expr) => {
        expand_main!($round, $enc_keys, $pos);

        let n = $pos+1;
        asm!("
            aeskeygenassist xmm4, xmm1, 0x00

            pshufd xmm2, xmm4, 0xaa

            movdqa xmm4, xmm3
            pslldq xmm4, 0x4
            pxor xmm3, xmm4

            pslldq xmm4, 0x4
            pxor xmm3, xmm4

            pslldq xmm4, 0x4
            pxor xmm3, xmm4

            pxor xmm3, xmm2
            aesimc xmm0, xmm1
            aesimc xmm5, xmm3
            "
            : "={xmm3}"($enc_keys[n]),
                "={xmm0}"($dec_keys[$pos]), "={xmm5}"($dec_keys[n])
            : "{xmm1}"($enc_keys[$pos]), "{xmm3}"($enc_keys[$pos-1])
            : "xmm2", "xmm4"
            : "intel", "alignstack", "volatile"
        );
    }
}

#[inline]
pub(super) fn expand(key: &[u8; 32]) -> ([u64x2; 15], [u64x2; 15]) {
    let key = *key;
    let mut enc_keys = [u64x2(0, 0); 15];
    let mut dec_keys = [u64x2(0, 0); 15];

    unsafe {
        let k1 = &*(key.as_ptr() as *const [u8; 16]);
        let k2 = &*(key.as_ptr().offset(16) as *const [u8; 16]);

        enc_keys[0] = u64x2::read(k1);
        dec_keys[0] = enc_keys[0];
        enc_keys[1] = u64x2::read(k2);

        asm!(
            "aesimc xmm0, xmm1"
            : "={xmm0}"(dec_keys[1])
            : "{xmm1}"(enc_keys[1])
            :
            : "intel", "alignstack"
        );

        expand_round!("0x01", enc_keys, dec_keys, 2);
        expand_round!("0x02", enc_keys, dec_keys, 4);
        expand_round!("0x04", enc_keys, dec_keys, 6);
        expand_round!("0x08", enc_keys, dec_keys, 8);
        expand_round!("0x10", enc_keys, dec_keys, 10);
        expand_round!("0x20", enc_keys, dec_keys, 12);
        expand_round_last!("0x40", enc_keys, dec_keys, 14);
    }

    (enc_keys, dec_keys)
}
