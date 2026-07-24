use crate::Block;
use cipher::{
    Array,
    array::ArraySize,
    consts::{U2, U4},
};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr};

/// Width-abstracted machine word holding one row of a bitsliced AES state.
pub(crate) trait Word:
    Sized
    + Copy
    + Default
    + 'static
    + BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
{
    /// Number of 128-bit blocks bitsliced together in one state.
    type Blocks: ArraySize;

    /// Width in bits of one row of the bitsliced state (8 for `u32`, 16 for `u64`).
    const ROW_BITS: u32 = (size_of::<Self>() * 2) as u32;

    /// Half of `ROW_BITS`.
    const HALF_ROW: u32 = Self::ROW_BITS / 2;
    /// Quarter of `ROW_BITS`.
    const QUARTER_ROW: u32 = Self::ROW_BITS / 4;

    /// Distance in bits to rotate a state row by `(rows, cols)` positions.
    #[inline(always)]
    fn ror_distance(rows: u32, cols: u32) -> u32 {
        rows * Self::ROW_BITS + cols * Self::QUARTER_ROW
    }

    /// Rotate right by `n` bits.
    fn ror(self, n: u32) -> Self;

    /// Pack the same byte across all 4 rows of the word.
    fn uniform_row(b: u8) -> Self;

    /// Place one byte at each of the 4 row positions of the word (row 0 = LSB).
    fn pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> Self;

    /// Replicate byte `b` across every byte of the word.
    fn byte_repeat(b: u8) -> Self;

    /// Pack `Self::Blocks` input blocks into a bitsliced 8-row state slice.
    fn bitslice(output: &mut [Self], input: &Array<Block, Self::Blocks>);

    /// Unpack a bitsliced 8-row state slice into `Self::Blocks` output blocks.
    fn inv_bitslice(input: &[Self]) -> Array<Block, Self::Blocks>;
}

impl Word for u32 {
    type Blocks = U2;

    #[inline(always)]
    fn ror(self, n: u32) -> u32 {
        self.rotate_right(n)
    }

    #[inline(always)]
    fn uniform_row(b: u8) -> u32 {
        (b as u32) * 0x01010101
    }

    #[inline(always)]
    fn pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> u32 {
        (r0 as u32) | ((r1 as u32) << 8) | ((r2 as u32) << 16) | ((r3 as u32) << 24)
    }

    #[inline(always)]
    fn byte_repeat(b: u8) -> u32 {
        (b as u32) * 0x01010101
    }

    /// Bitslice two 128-bit input blocks into a 256-bit internal state.
    fn bitslice(output: &mut [u32], input: &Array<Block, U2>) {
        debug_assert_eq!(output.len(), 8);
        let input0 = input[0].as_slice();
        let input1 = input[1].as_slice();

        // Bitslicing is a bit index manipulation. 256 bits of data means each bit is positioned at
        // an 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so the
        // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The desired bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b0

        // Interleave the columns on input (note the order of input)
        //     b0 c1 c0 __ __ __ __ __ => c1 c0 b0 __ __ __ __ __
        let mut t = [
            u32::from_le_bytes(input0[0x00..0x04].try_into().unwrap()),
            u32::from_le_bytes(input1[0x00..0x04].try_into().unwrap()),
            u32::from_le_bytes(input0[0x04..0x08].try_into().unwrap()),
            u32::from_le_bytes(input1[0x04..0x08].try_into().unwrap()),
            u32::from_le_bytes(input0[0x08..0x0c].try_into().unwrap()),
            u32::from_le_bytes(input1[0x08..0x0c].try_into().unwrap()),
            u32::from_le_bytes(input0[0x0c..0x10].try_into().unwrap()),
            u32::from_le_bytes(input1[0x0c..0x10].try_into().unwrap()),
        ];

        bitslice_swaps(&mut t);

        // Final bitsliced bit index, as desired:
        //     p2 p1 p0 r1 r0 c1 c0 b0
        output[..8].copy_from_slice(&t);
    }

    /// Un-bitslice a 256-bit internal state into two 128-bit blocks.
    fn inv_bitslice(input: &[u32]) -> Array<Block, U2> {
        debug_assert_eq!(input.len(), 8);

        // Unbitslicing is a bit index manipulation. 256 bits of data means each bit is positioned
        // at an 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so
        // the desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The initially bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b0

        let mut t = [
            input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
        ];

        bitslice_swaps(&mut t);

        let mut output = Array::<Block, U2>::default();
        // De-interleave the columns on output (note the order of output)
        //     c1 c0 b0 __ __ __ __ __ => b0 c1 c0 __ __ __ __ __
        output[0][0x00..0x04].copy_from_slice(&t[0].to_le_bytes());
        output[0][0x04..0x08].copy_from_slice(&t[2].to_le_bytes());
        output[0][0x08..0x0c].copy_from_slice(&t[4].to_le_bytes());
        output[0][0x0c..0x10].copy_from_slice(&t[6].to_le_bytes());
        output[1][0x00..0x04].copy_from_slice(&t[1].to_le_bytes());
        output[1][0x04..0x08].copy_from_slice(&t[3].to_le_bytes());
        output[1][0x08..0x0c].copy_from_slice(&t[5].to_le_bytes());
        output[1][0x0c..0x10].copy_from_slice(&t[7].to_le_bytes());

        // Final AES bit index, as desired:
        //     b0 c1 c0 r1 r0 p2 p1 p0
        output
    }
}

/// Expand an 8-bit row pattern to a 16-bit row pattern by doubling each bit:
/// input bit `i` becomes output bits `2i` and `2i+1`. Branchless SWAR so LLVM
/// folds it to a single 16-bit immediate when `b` is a constant.
#[inline(always)]
const fn double_bits(b: u8) -> u16 {
    let x = b as u16;
    // Spread the 8 bits of x to even positions 0,2,4,6,8,10,12,14.
    let x = (x | (x << 4)) & 0x0f0f;
    let x = (x | (x << 2)) & 0x3333;
    let x = (x | (x << 1)) & 0x5555;
    // Duplicate each spread bit to its adjacent odd position.
    x | (x << 1)
}

impl Word for u64 {
    type Blocks = U4;

    #[inline(always)]
    fn ror(self, n: u32) -> u64 {
        self.rotate_right(n)
    }

    #[inline(always)]
    fn uniform_row(b: u8) -> u64 {
        (double_bits(b) as u64) * 0x0001_0001_0001_0001
    }

    #[inline(always)]
    fn pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> u64 {
        (double_bits(r0) as u64)
            | ((double_bits(r1) as u64) << 16)
            | ((double_bits(r2) as u64) << 32)
            | ((double_bits(r3) as u64) << 48)
    }

    #[inline(always)]
    fn byte_repeat(b: u8) -> u64 {
        (b as u64) * 0x0101010101010101
    }

    /// Bitslice four 128-bit input blocks into a 512-bit internal state.
    fn bitslice(output: &mut [u64], input: &Array<Block, U4>) {
        debug_assert_eq!(output.len(), 8);

        // Bitslicing is a bit index manipulation. 512 bits of data means each bit is positioned at
        // a 9-bit index. AES data is 4 blocks, each one a 4x4 column-major matrix of bytes, so the
        // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b1 b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The desired bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b1 b0

        #[rustfmt::skip]
        fn read_reordered(input: &[u8]) -> u64 {
            (u64::from(input[0x0])        ) |
            (u64::from(input[0x1]) << 0x10) |
            (u64::from(input[0x2]) << 0x20) |
            (u64::from(input[0x3]) << 0x30) |
            (u64::from(input[0x8]) << 0x08) |
            (u64::from(input[0x9]) << 0x18) |
            (u64::from(input[0xa]) << 0x28) |
            (u64::from(input[0xb]) << 0x38)
        }

        // Reorder each block's bytes on input
        //     __ __ c1 c0 r1 r0 __ __ __ => __ __ c0 r1 r0 c1 __ __ __
        // Reorder by relabeling (note the order of input)
        //     b1 b0 c0 __ __ __ __ __ __ => c0 b1 b0 __ __ __ __ __ __
        let mut t = [
            read_reordered(&input[0][0x00..0x0c]),
            read_reordered(&input[1][0x00..0x0c]),
            read_reordered(&input[2][0x00..0x0c]),
            read_reordered(&input[3][0x00..0x0c]),
            read_reordered(&input[0][0x04..0x10]),
            read_reordered(&input[1][0x04..0x10]),
            read_reordered(&input[2][0x04..0x10]),
            read_reordered(&input[3][0x04..0x10]),
        ];

        bitslice_swaps(&mut t);

        // Final bitsliced bit index, as desired:
        //     p2 p1 p0 r1 r0 c1 c0 b1 b0
        output[..8].copy_from_slice(&t);
    }

    /// Un-bitslice a 512-bit internal state into four 128-bit blocks.
    fn inv_bitslice(input: &[u64]) -> Array<Block, U4> {
        debug_assert_eq!(input.len(), 8);

        // Unbitslicing is a bit index manipulation. 512 bits of data means each bit is positioned
        // at a 9-bit index. AES data is 4 blocks, each one a 4x4 column-major matrix of bytes, so
        // the desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b1 b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The initially bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b1 b0

        let mut t = [
            input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
        ];

        bitslice_swaps(&mut t);

        #[rustfmt::skip]
        fn write_reordered(columns: u64, output: &mut [u8]) {
            output[0x0] = (columns        ) as u8;
            output[0x1] = (columns >> 0x10) as u8;
            output[0x2] = (columns >> 0x20) as u8;
            output[0x3] = (columns >> 0x30) as u8;
            output[0x8] = (columns >> 0x08) as u8;
            output[0x9] = (columns >> 0x18) as u8;
            output[0xa] = (columns >> 0x28) as u8;
            output[0xb] = (columns >> 0x38) as u8;
        }

        let mut output = Array::<Block, U4>::default();
        // Reorder by relabeling (note the order of output)
        //     c0 b1 b0 __ __ __ __ __ __ => b1 b0 c0 __ __ __ __ __ __
        // Reorder each block's bytes on output
        //     __ __ c0 r1 r0 c1 __ __ __ => __ __ c1 c0 r1 r0 __ __ __
        write_reordered(t[0], &mut output[0][0x00..0x0c]);
        write_reordered(t[4], &mut output[0][0x04..0x10]);
        write_reordered(t[1], &mut output[1][0x00..0x0c]);
        write_reordered(t[5], &mut output[1][0x04..0x10]);
        write_reordered(t[2], &mut output[2][0x00..0x0c]);
        write_reordered(t[6], &mut output[2][0x04..0x10]);
        write_reordered(t[3], &mut output[3][0x00..0x0c]);
        write_reordered(t[7], &mut output[3][0x04..0x10]);

        // Final AES bit index, as desired:
        //     b1 b0 c1 c0 r1 r0 p2 p1 p0
        output
    }
}

/// Width-generic delta-swap pipeline shared by `bitslice` and `inv_bitslice`
/// across every `Word` impl. The same three-pass sequence inverts itself, so
/// `bitslice` and `inv_bitslice` invoke it identically.
///
/// The diagrams below describe the `u32` case (8-bit rows); for `u64` each
/// bit position widens by one, but the swap structure is unchanged.
#[inline(always)]
fn bitslice_swaps<W: Word>(t: &mut [W; 8]) {
    use super::utils::delta_swap_2;
    let [t0, t1, t2, t3, t4, t5, t6, t7] = t;

    // Bit Index Swap 5 <-> 0:
    //     __ __ b0 __ __ __ __ p0 => __ __ p0 __ __ __ __ b0
    let m0 = W::byte_repeat(0x55);
    delta_swap_2(t1, t0, 1, m0);
    delta_swap_2(t3, t2, 1, m0);
    delta_swap_2(t5, t4, 1, m0);
    delta_swap_2(t7, t6, 1, m0);

    // Bit Index Swap 6 <-> 1:
    //     __ c0 __ __ __ __ p1 __ => __ p1 __ __ __ __ c0 __
    let m1 = W::byte_repeat(0x33);
    delta_swap_2(t2, t0, 2, m1);
    delta_swap_2(t3, t1, 2, m1);
    delta_swap_2(t6, t4, 2, m1);
    delta_swap_2(t7, t5, 2, m1);

    // Bit Index Swap 7 <-> 2:
    //     c1 __ __ __ __ p2 __ __ => p2 __ __ __ __ c1 __ __
    let m2 = W::byte_repeat(0x0f);
    delta_swap_2(t4, t0, 4, m2);
    delta_swap_2(t5, t1, 4, m2);
    delta_swap_2(t6, t2, 4, m2);
    delta_swap_2(t7, t3, 4, m2);
}
