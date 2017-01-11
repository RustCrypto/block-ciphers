use sboxes;
use sboxes_exp;

fn gen_exp_sbox(sbox: sboxes::SBox) -> sboxes_exp::SBoxExp {
    let mut out = [[0u8; 256]; 4];
    for i in 0..4 {
        for j in 0..16 {
            for k in 0..16 {
                let v: u8 = sbox[2*i][j] + (sbox[2*i+1][k]<<4);
                let c: usize = j + (k<<4);
                out[i][c] = v;
            }
        }
    }
    out
}

fn test_sbox(sbox: sboxes::SBox, sbox_exp: sboxes_exp::SBoxExp) {
    let gen_sbox = gen_exp_sbox(sbox);
    for i in 0..4 {
        for j in 0..256 {
            assert_eq!(gen_sbox[i][j], sbox_exp[i][j]);
        }
    }
}

#[test]
fn test_sboxes() {
    test_sbox(sboxes::S_TC26, sboxes_exp::S_TC26);
    test_sbox(sboxes::S_TEST, sboxes_exp::S_TEST);
    test_sbox(sboxes::S_CRYPTOPRO_A, sboxes_exp::S_CRYPTOPRO_A);
    test_sbox(sboxes::S_CRYPTOPRO_B, sboxes_exp::S_CRYPTOPRO_B);
    test_sbox(sboxes::S_CRYPTOPRO_C, sboxes_exp::S_CRYPTOPRO_C);
    test_sbox(sboxes::S_CRYPTOPRO_D, sboxes_exp::S_CRYPTOPRO_D);
}