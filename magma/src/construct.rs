macro_rules! constuct_cipher {
    ($name:ident, $sbox:expr) => {

        #[derive(Clone, Copy)]
        pub struct $name {
            c: Gost89
        }

        impl BlockCipher for $name {
            type KeySize = U32;
            type BlockSize = U8;
            type ParBlocks = U1;

            fn new(key: &GenericArray<u8, U32>) -> Self {
                let mut c = Gost89 { sbox: &$sbox, key: Default::default() };
                LE::read_u32_into(key, &mut c.key);
                Self { c }
            }

            #[inline]
            fn encrypt_block(&self, block: &mut Block) {
                self.c.encrypt(block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut Block) {
                self.c.decrypt(block);
            }
        }

        impl_opaque_debug!($name);
    }
}
