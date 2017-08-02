use u64x2::u64x2;

macro_rules! expand_round {
    ($round:expr, $enc_keys:ident, $dec_keys:ident, $pos:expr) => {
        asm!(concat!("
            aeskeygenassist xmm2, xmm1, ", $round,
            "
            pshufd xmm2, xmm2, 0xff

            movdqa xmm3, xmm1
            pslldq xmm3, 0x4
            pxor xmm1, xmm3

            pslldq xmm3, 0x4
            pxor xmm1, xmm3

            pslldq xmm3, 0x4
            pxor xmm1, xmm3

            pxor xmm1, xmm2
            aesimc xmm0, xmm1
            ")
            : "={xmm1}"($enc_keys[$pos])
            : "{xmm1}"($enc_keys[$pos-1])
            : "xmm2", "xmm3"
            : "intel", "alignstack", "volatile"
        );
        if $pos != 10 {
            asm!(
                "aesimc xmm0, xmm1"
                : "={xmm0}"($dec_keys[$pos])
                : "{xmm1}"($enc_keys[$pos])
                :
                : "intel", "alignstack", "volatile"
            );
        } else {
            $dec_keys[$pos] = $enc_keys[$pos];
        }
    }
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 16]) -> ([u64x2; 11], [u64x2; 11]) {
    let mut enc_keys = [u64x2(0, 0); 11];
    let mut dec_keys = [u64x2(0, 0); 11];
    enc_keys[0] = u64x2::read(key);
    dec_keys[0] = enc_keys[0];

    unsafe {
        expand_round!("0x01", enc_keys, dec_keys, 1);
        expand_round!("0x02", enc_keys, dec_keys, 2);
        expand_round!("0x04", enc_keys, dec_keys, 3);
        expand_round!("0x08", enc_keys, dec_keys, 4);
        expand_round!("0x10", enc_keys, dec_keys, 5);
        expand_round!("0x20", enc_keys, dec_keys, 6);
        expand_round!("0x40", enc_keys, dec_keys, 7);
        expand_round!("0x80", enc_keys, dec_keys, 8);
        expand_round!("0x1b", enc_keys, dec_keys, 9);
        expand_round!("0x36", enc_keys, dec_keys, 10);
    }

    (enc_keys, dec_keys)
}
