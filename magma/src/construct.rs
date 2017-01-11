
macro_rules! constuct_cipher {
    ($name:ident, $sbox:expr) => {

        #[derive(Clone, Copy)]
        pub struct $name<'a> {
            c: Gost89<'a>
        }

        impl<'a> BlockCipher for $name<'a> {
            type BlockSize = U8;

            fn encrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
                self.c.encrypt_block(input, output);
            }

            fn decrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
                self.c.decrypt_block(input, output);
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