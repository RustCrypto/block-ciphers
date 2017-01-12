//! Strictly speaking this code is not neccecary and duplicates main code,
//! but there is no convienient way to convert &Block<U16> to [u8; 16]
//! without perfomance hit
use consts;

fn l_step(msg: &mut [u8; 16], i: usize) {
    let mut x = msg[i];
    x ^= consts::GF[3][msg[(1+i) & 0xf] as usize];
    x ^= consts::GF[1][msg[(2+i) & 0xf] as usize];
    x ^= consts::GF[2][msg[(3+i) & 0xf] as usize];
    x ^= consts::GF[0][msg[(4+i) & 0xf] as usize];
    x ^= consts::GF[5][msg[(5+i) & 0xf] as usize];
    x ^= consts::GF[4][msg[(6+i) & 0xf] as usize];
    x ^= msg[(7+i) & 0xf];
    x ^= consts::GF[6][msg[(8+i) & 0xf] as usize];
    x ^= msg[(9+i) & 0xf];
    x ^= consts::GF[4][msg[(10+i) & 0xf] as usize];
    x ^= consts::GF[5][msg[(11+i) & 0xf] as usize];
    x ^= consts::GF[0][msg[(12+i) & 0xf] as usize];
    x ^= consts::GF[2][msg[(13+i) & 0xf] as usize];
    x ^= consts::GF[1][msg[(14+i) & 0xf] as usize];
    x ^= consts::GF[3][msg[(15+i) & 0xf] as usize];
    msg[i] = x;
}

fn x(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l(msg: &mut [u8; 16]) {
    for i in 0..16 {
        l_step(msg, i);
    }
}

fn get_c(n: usize) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0] = n as u8;
    l(&mut v);
    v
}

fn lsx(msg: &mut [u8; 16], key: &[u8; 16]) {
    x(msg, key);
    // s
    for i in 0..16 {
        msg[i] = consts::P[msg[i] as usize];
    }
    l(msg);
}

pub fn f(k1: &mut [u8; 16], k2: &mut [u8; 16], n: usize) {
    for i in 0..4 {
        let mut k1_cpy = k1.clone();
        lsx(&mut k1_cpy, &get_c(8*n+2*i+1));
        x(k2, &k1_cpy);

        let mut k2_cpy = k2.clone();
        lsx(&mut k2_cpy, &get_c(8*n+2*i+2));
        x(k1, &k2_cpy);        
    }
}
