#[cfg(test)]
mod tests {
    use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
    use rc5::RC5_32_20_16;

    #[test]
    fn enc_dec_32_20_16() {
        // https://www.ietf.org/archive/id/draft-krovetz-rc6-rc5-vectors-00.txt
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let ct = [0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];

        let rc5 = <RC5_32_20_16 as KeyInit>::new_from_slice(&key).unwrap();

        let mut block = GenericArray::clone_from_slice(&pt);
        rc5.encrypt_block(&mut block);

        assert_eq!(ct, block[..]);

        rc5.decrypt_block(&mut block);
        assert_eq!(pt, block[..]);
    }
}
