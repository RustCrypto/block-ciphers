// TODO: use u128 tables after MSRV is bumped to 1.77 or higher
#[repr(align(16))]
pub(crate) struct Align16<T>(pub T);

impl<T> Align16<T> {
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const u128 {
        self as *const Self as *const u128
    }
}

pub(crate) type Table = Align16<[u8; 16 * 4096]>;

pub(crate) static ENC_TABLE: Table = Align16(*include_bytes!("enc_table.bin"));

pub(crate) static DEC_TABLE: Table = Align16(*include_bytes!("dec_table.bin"));

pub(crate) static RKEY_GEN: Align16<[u8; 16 * 32]> = Align16(*include_bytes!("rkey_gen.bin"));
