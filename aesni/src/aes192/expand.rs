use core::ptr::copy_nonoverlapping;
use u64x2::u64x2;

macro_rules! inverse_key {
    ($dec_key:expr, $enc_key:expr) => {
        asm!(
            "aesimc xmm0, xmm1"
            : "={xmm0}"($dec_key)
            : "{xmm1}"($enc_key)
            :
            : "intel", "alignstack", "volatile"
        );
    }
}

macro_rules! expand_round {
    (
        $round:expr, $enc_keys:ident, $dec_keys:ident, $pos:expr,
        $odd:expr, $t1:ident, $t3:ident
    ) => {
        asm!(concat!(
            "aeskeygenassist xmm2, xmm3, ", $round,
            "
            pshufd xmm2, xmm2, 0x55

            movdqa xmm4, xmm1
            pslldq xmm4, 0x4
            pxor xmm1, xmm4

            pslldq xmm4, 0x4
            pxor xmm1, xmm4

            pslldq xmm4, 0x4
            pxor xmm1, xmm4

            pxor xmm1, xmm2

            pshufd xmm2, xmm1, 0xff
            movdqa xmm4, xmm3
            pslldq xmm4, 0x4

            pxor xmm3, xmm4
            pxor xmm3, xmm2
            ")
            : "+{xmm1}"($t1), "+{xmm3}"($t3)
            :
            : "xmm2", "xmm4"
            : "intel", "alignstack", "volatile"
        );
        if $odd {
            $enc_keys[$pos] = $t1;
            if $pos != 12 {
                inverse_key!($dec_keys[$pos], $t1);
                $enc_keys[$pos+1] = $t3;
            } else {
                $dec_keys[$pos] = $enc_keys[$pos];
            }
        } else {
            $enc_keys[$pos].1 = $t1.0;
            inverse_key!($dec_keys[$pos], $enc_keys[$pos]);
            let n = $pos+1;
            $enc_keys[n].0 = $t1.1;
            $enc_keys[n].1 = $t3.0;
            inverse_key!($dec_keys[n], $enc_keys[n]);
        }
    }
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 24]) -> ([u64x2; 13], [u64x2; 13]) {
    let key = *key;
    let mut enc_keys = [u64x2(0, 0); 13];
    let mut dec_keys = [u64x2(0, 0); 13];

    unsafe {
        let k1 = &*(key.as_ptr() as *const [u8; 16]);

        enc_keys[0] = u64x2::read(k1);
        dec_keys[0] = enc_keys[0];
        // copy half of the second key
        copy_nonoverlapping(
            key.as_ptr().offset(16),
            &mut enc_keys[1].0 as *mut u64 as *mut u8,
            8,
        );

        let mut t1 = enc_keys[0];
        let mut t3 = enc_keys[1];

        expand_round!("0x01", enc_keys, dec_keys, 1, false, t1, t3);
        expand_round!("0x02", enc_keys, dec_keys, 3, true, t1, t3);
        expand_round!("0x04", enc_keys, dec_keys, 4, false, t1, t3);
        expand_round!("0x08", enc_keys, dec_keys, 6, true, t1, t3);
        expand_round!("0x10", enc_keys, dec_keys, 7, false, t1, t3);
        expand_round!("0x20", enc_keys, dec_keys, 9, true, t1, t3);
        expand_round!("0x40", enc_keys, dec_keys, 10, false, t1, t3);
        expand_round!("0x80", enc_keys, dec_keys, 12, true, t1, t3);
    }

    (enc_keys, dec_keys)
}
