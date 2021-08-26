#[repr(align(16))]
pub struct Align16<T>(pub T);

pub type Table = Align16<[u8; 16 * 4096]>;

pub static ENC_TABLE: Table = Align16(*include_bytes!("enc_table.bin"));

pub static DEC_TABLE: Table = Align16(*include_bytes!("dec_table.bin"));

pub static RKEY_GEN: Align16<[u8; 16 * 32]> = Align16(*include_bytes!("rkey_gen.bin"));
