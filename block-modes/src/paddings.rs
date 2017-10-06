use traits::{Padding, UnpadError};
use core::ptr;

pub enum ZeroPadding{}

impl Padding for ZeroPadding {
    fn pad(block: &mut [u8], pos: usize) {
        zero(&mut block[pos..])
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        let mut n = data.len() - 1;
        while n != 0 {
            if data[n] != 0 {
                break;
            }
            n -= 1;
        }
        Ok(&data[..n+1])
    }
}

pub enum Pkcs7{}

impl Padding for Pkcs7 {
    fn pad(block: &mut [u8], pos: usize) {
        let n = block.len() - pos;
        set(&mut block[pos..], n as u8);
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        if data.is_empty() { return Err(UnpadError); }
        let l = data.len();
        let n = data[l-1];
        if n == 0 {
            return Err(UnpadError)
        }
        for v in &data[l-n as usize..l-1] {
            if *v != n { return Err(UnpadError); }
        }
        Ok(&data[..l-n as usize])
    }
}

pub enum AnsiX923{}

impl Padding for AnsiX923 {
    fn pad(block: &mut [u8], pos: usize) {
        let n = block.len() - 1;
        zero(&mut block[pos..n]);
        block[n] = (n - pos) as u8;
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        if data.is_empty() { return Err(UnpadError); }
        let l = data.len();
        let n = data[l-1] as usize;
        if n == 0 {
            return Err(UnpadError)
        }
        for v in &data[l-n..l-1] {
            if *v != 0 { return Err(UnpadError); }
        }
        Ok(&data[..l-n])
    }
}

pub enum Iso7816{}

impl Padding for Iso7816 {
    fn pad(block: &mut [u8], pos: usize) {
        let n = block.len() - pos;
        block[pos] = 0x80;
        for b in block[pos+1..].iter_mut() {
            *b = n as u8;
        }
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        if data.is_empty() { return Err(UnpadError); }
        let mut n = data.len() - 1;
        while n != 0 {
            if data[n] != 0 {
                break;
            }
            n -= 1;
        }
        if data[n] != 0x80 { return Err(UnpadError); }
        Ok(&data[..n])
    }
}


// Take from byte-tools ?
/// Zero all bytes in dst
#[inline]
pub fn zero(dst: &mut [u8]) {
    set(dst, 0);
}

/// Sets all bytes in `dst` equal to `value`
#[inline]
pub fn set(dst: &mut [u8], value: u8) {
    unsafe {
        ptr::write_bytes(dst.as_mut_ptr(), value, dst.len());
    }
}
