macro_rules! construct_cipher {
    ($name:ident, $sbox:expr) => {
        #[derive(Clone, Copy)]
        pub struct $name {
            c: Gost89,
        }

        impl NewBlockCipher for $name {
            type KeySize = U32;

            fn new(key: &GenericArray<u8, U32>) -> Self {
                let mut c = Gost89 {
                    sbox: &$sbox,
                    key: Default::default(),
                };
                LE::read_u32_into(key, &mut c.key);
                Self { c }
            }
        }

        impl BlockCipher for $name {
            type BlockSize = U8;
            type ParBlocks = U1;

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
    };
}
