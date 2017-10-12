use core::ptr::copy_nonoverlapping;
use core::mem;

#[allow(non_camel_case_types)]
#[repr(simd)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct u64x2(pub u64, pub u64);

const BSWAP_EPI_64: u64x2 = u64x2(0x0001020304050607, 0x08090a0b0c0d0e0f);

impl u64x2 {
    /// Reads u64x2 from array pointer (potentially unaligned)
    #[inline(always)]
    pub fn read(src: &[u8; 16]) -> Self {
        unsafe {
            let mut tmp: Self = mem::uninitialized();
            copy_nonoverlapping(
                src.as_ptr(),
                &mut tmp as *mut Self as *mut u8,
                16,
            );
            tmp
        }
    }

    /// Write u64x2 content into array pointer (potentially unaligned)
    #[inline(always)]
    pub fn write(self, dst: &mut [u8; 16]) {
        unsafe {
            copy_nonoverlapping(
                &self as *const Self as *const u8,
                dst.as_mut_ptr(),
                16,
            );
        }
    }

    /// Read [u64x2; 8] from array pointer (potentially unaligned)
    #[inline(always)]
    pub fn read8(src: &[u8; 16*8]) -> [Self; 8] {
        unsafe {
            let mut tmp: [Self; 8] = mem::uninitialized();
            copy_nonoverlapping(
                src.as_ptr(),
                &mut tmp as *mut [Self; 8] as *mut u8,
                16*8,
            );
            tmp
        }
    }

    /// Write [u64x2; 8] content into array pointer (potentially unaligned)
    #[inline(always)]
    pub fn write8(src: [u64x2; 8], dst: &mut [u8; 16*8]) {
        unsafe {
            copy_nonoverlapping(
                &src as *const [Self; 8] as *const u8,
                dst.as_mut_ptr(),
                16*8,
            );
        }
    }

    #[inline(always)]
    /// increments last u64 without carry using paddq instruction, so
    /// it can be done without moving from XMM register
    pub fn inc_be(&mut self) {
        unsafe{
          asm!("paddq $0, $1"
            :"+x"(*self)
            :"x"(u64x2(0, 1))
            :
            :"intel"
          );
        }
    }

    #[inline(always)]
    /// Convert to big-endiann representation
    pub fn swap_bytes(&self) -> u64x2 {
        let mut val = *self;
        unsafe{
          asm!("pshufb $0, $1"
            :"+x"(val)
            :"x"(BSWAP_EPI_64)
            :
            :"intel"
          );
        }
        val
    }
}
