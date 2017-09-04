
macro_rules! constuct_cipher {
    ($name:ident, $sbox:expr) => {

        #[derive(Clone, Copy)]
        pub struct $name<'a> {
            c: Gost89<'a>
        }

        impl<'a> BlockCipher for $name<'a> {
            type BlockSize = U8;

            #[inline]
            fn encrypt_block(&self, block: &mut Block<U8>) {
                self.c.encrypt_block(block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut Block<U8>) {
                self.c.decrypt_block(block);
            }
        }

        impl<'a> BlockCipherFixKey for $name<'a> {
            type KeySize = U32;

            fn new(key: &GenericArray<u8, U32>) -> Self {
                $name{c: Gost89::new(key, &$sbox)}
            }
        }

    }
}