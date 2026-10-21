use crate::consts;

pub fn keys(mk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    
    let delta = &consts::DELTA;
    let mut sk = vec![0u8; 128]; 

    for i in 0usize..8 {
        for j in 0usize..16 {
            let mk_index = (j.wrapping_sub(i)) % 8 + (j / 8) * 8;

            let a = mk[15 - mk_index]; 
            let b = delta[16 * i + j];

            sk[16 * i + j] = a.wrapping_add(b);
        }
    }

	let wk: Vec<u8> = (0..8).map(|i| mk[if i <= 3 { 3 - i } else { 19 - i }]).collect();
    (wk, sk)
}
