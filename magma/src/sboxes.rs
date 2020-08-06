//! Expanded S-boxes generated using `gen_exp_sbox` function

type ExpSbox = [[u8; 256]; 4];
type SmallSbox = [[u8; 16]; 8];

/// Trait implemented for the GOST 28147-89 cipher S-boxes
pub trait Sbox {
    /// Expanded S-box
    const EXP_SBOX: ExpSbox;

    /// Unexpanded S-box
    const SBOX: SmallSbox;

    fn gen_exp_sbox() -> ExpSbox {
        let mut out = [[0u8; 256]; 4];
        for i in 0..4 {
            for j in 0..16 {
                for k in 0..16 {
                    let v: u8 = Self::SBOX[2 * i][j] + (Self::SBOX[2 * i + 1][k] << 4);
                    let c: usize = j + (k << 4);
                    out[i][c] = v;
                }
            }
        }
        out
    }

    fn apply_sbox(a: u32) -> u32 {
        let mut v = 0;
        for i in 0..4 {
            let shft = 8 * i;
            let k = ((a & (0xffu32 << shft)) >> shft) as usize;
            v += (Self::EXP_SBOX[i][k] as u32) << shft;
        }
        v
    }

    fn g(a: u32, k: u32) -> u32 {
        Self::apply_sbox(a.wrapping_add(k)).rotate_left(11)
    }
}

pub enum Tc26 {}

impl Sbox for Tc26 {
    const EXP_SBOX: ExpSbox = [
        [
            108, 100, 102, 98, 106, 101, 107, 105, 110, 104, 109, 103, 96, 99, 111, 97, 140, 132,
            134, 130, 138, 133, 139, 137, 142, 136, 141, 135, 128, 131, 143, 129, 44, 36, 38, 34,
            42, 37, 43, 41, 46, 40, 45, 39, 32, 35, 47, 33, 60, 52, 54, 50, 58, 53, 59, 57, 62, 56,
            61, 55, 48, 51, 63, 49, 156, 148, 150, 146, 154, 149, 155, 153, 158, 152, 157, 151,
            144, 147, 159, 145, 172, 164, 166, 162, 170, 165, 171, 169, 174, 168, 173, 167, 160,
            163, 175, 161, 92, 84, 86, 82, 90, 85, 91, 89, 94, 88, 93, 87, 80, 83, 95, 81, 204,
            196, 198, 194, 202, 197, 203, 201, 206, 200, 205, 199, 192, 195, 207, 193, 28, 20, 22,
            18, 26, 21, 27, 25, 30, 24, 29, 23, 16, 19, 31, 17, 236, 228, 230, 226, 234, 229, 235,
            233, 238, 232, 237, 231, 224, 227, 239, 225, 76, 68, 70, 66, 74, 69, 75, 73, 78, 72,
            77, 71, 64, 67, 79, 65, 124, 116, 118, 114, 122, 117, 123, 121, 126, 120, 125, 119,
            112, 115, 127, 113, 188, 180, 182, 178, 186, 181, 187, 185, 190, 184, 189, 183, 176,
            179, 191, 177, 220, 212, 214, 210, 218, 213, 219, 217, 222, 216, 221, 215, 208, 211,
            223, 209, 12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1, 252, 244, 246, 242,
            250, 245, 251, 249, 254, 248, 253, 247, 240, 243, 255, 241,
        ],
        [
            203, 195, 197, 200, 194, 207, 202, 205, 206, 193, 199, 196, 204, 201, 198, 192, 139,
            131, 133, 136, 130, 143, 138, 141, 142, 129, 135, 132, 140, 137, 134, 128, 43, 35, 37,
            40, 34, 47, 42, 45, 46, 33, 39, 36, 44, 41, 38, 32, 27, 19, 21, 24, 18, 31, 26, 29, 30,
            17, 23, 20, 28, 25, 22, 16, 219, 211, 213, 216, 210, 223, 218, 221, 222, 209, 215, 212,
            220, 217, 214, 208, 75, 67, 69, 72, 66, 79, 74, 77, 78, 65, 71, 68, 76, 73, 70, 64,
            251, 243, 245, 248, 242, 255, 250, 253, 254, 241, 247, 244, 252, 249, 246, 240, 107,
            99, 101, 104, 98, 111, 106, 109, 110, 97, 103, 100, 108, 105, 102, 96, 123, 115, 117,
            120, 114, 127, 122, 125, 126, 113, 119, 116, 124, 121, 118, 112, 11, 3, 5, 8, 2, 15,
            10, 13, 14, 1, 7, 4, 12, 9, 6, 0, 171, 163, 165, 168, 162, 175, 170, 173, 174, 161,
            167, 164, 172, 169, 166, 160, 91, 83, 85, 88, 82, 95, 90, 93, 94, 81, 87, 84, 92, 89,
            86, 80, 59, 51, 53, 56, 50, 63, 58, 61, 62, 49, 55, 52, 60, 57, 54, 48, 235, 227, 229,
            232, 226, 239, 234, 237, 238, 225, 231, 228, 236, 233, 230, 224, 155, 147, 149, 152,
            146, 159, 154, 157, 158, 145, 151, 148, 156, 153, 150, 144, 187, 179, 181, 184, 178,
            191, 186, 189, 190, 177, 183, 180, 188, 185, 182, 176,
        ],
        [
            87, 95, 85, 90, 88, 81, 86, 93, 80, 89, 83, 94, 91, 84, 82, 92, 215, 223, 213, 218,
            216, 209, 214, 221, 208, 217, 211, 222, 219, 212, 210, 220, 247, 255, 245, 250, 248,
            241, 246, 253, 240, 249, 243, 254, 251, 244, 242, 252, 103, 111, 101, 106, 104, 97,
            102, 109, 96, 105, 99, 110, 107, 100, 98, 108, 151, 159, 149, 154, 152, 145, 150, 157,
            144, 153, 147, 158, 155, 148, 146, 156, 39, 47, 37, 42, 40, 33, 38, 45, 32, 41, 35, 46,
            43, 36, 34, 44, 199, 207, 197, 202, 200, 193, 198, 205, 192, 201, 195, 206, 203, 196,
            194, 204, 167, 175, 165, 170, 168, 161, 166, 173, 160, 169, 163, 174, 171, 164, 162,
            172, 183, 191, 181, 186, 184, 177, 182, 189, 176, 185, 179, 190, 187, 180, 178, 188,
            119, 127, 117, 122, 120, 113, 118, 125, 112, 121, 115, 126, 123, 116, 114, 124, 135,
            143, 133, 138, 136, 129, 134, 141, 128, 137, 131, 142, 139, 132, 130, 140, 23, 31, 21,
            26, 24, 17, 22, 29, 16, 25, 19, 30, 27, 20, 18, 28, 71, 79, 69, 74, 72, 65, 70, 77, 64,
            73, 67, 78, 75, 68, 66, 76, 55, 63, 53, 58, 56, 49, 54, 61, 48, 57, 51, 62, 59, 52, 50,
            60, 231, 239, 229, 234, 232, 225, 230, 237, 224, 233, 227, 238, 235, 228, 226, 236, 7,
            15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12,
        ],
        [
            24, 30, 18, 21, 22, 25, 17, 28, 31, 20, 27, 16, 29, 26, 19, 23, 120, 126, 114, 117,
            118, 121, 113, 124, 127, 116, 123, 112, 125, 122, 115, 119, 232, 238, 226, 229, 230,
            233, 225, 236, 239, 228, 235, 224, 237, 234, 227, 231, 216, 222, 210, 213, 214, 217,
            209, 220, 223, 212, 219, 208, 221, 218, 211, 215, 8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11,
            0, 13, 10, 3, 7, 88, 94, 82, 85, 86, 89, 81, 92, 95, 84, 91, 80, 93, 90, 83, 87, 136,
            142, 130, 133, 134, 137, 129, 140, 143, 132, 139, 128, 141, 138, 131, 135, 56, 62, 50,
            53, 54, 57, 49, 60, 63, 52, 59, 48, 61, 58, 51, 55, 72, 78, 66, 69, 70, 73, 65, 76, 79,
            68, 75, 64, 77, 74, 67, 71, 248, 254, 242, 245, 246, 249, 241, 252, 255, 244, 251, 240,
            253, 250, 243, 247, 168, 174, 162, 165, 166, 169, 161, 172, 175, 164, 171, 160, 173,
            170, 163, 167, 104, 110, 98, 101, 102, 105, 97, 108, 111, 100, 107, 96, 109, 106, 99,
            103, 152, 158, 146, 149, 150, 153, 145, 156, 159, 148, 155, 144, 157, 154, 147, 151,
            200, 206, 194, 197, 198, 201, 193, 204, 207, 196, 203, 192, 205, 202, 195, 199, 184,
            190, 178, 181, 182, 185, 177, 188, 191, 180, 187, 176, 189, 186, 179, 183, 40, 46, 34,
            37, 38, 41, 33, 44, 47, 36, 43, 32, 45, 42, 35, 39,
        ],
    ];

    const SBOX: SmallSbox = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
    ];
}

pub enum TestSbox {}

impl Sbox for TestSbox {
    const EXP_SBOX: ExpSbox = [
        [
            228, 234, 233, 226, 237, 232, 224, 238, 230, 235, 225, 236, 231, 239, 229, 227, 180,
            186, 185, 178, 189, 184, 176, 190, 182, 187, 177, 188, 183, 191, 181, 179, 68, 74, 73,
            66, 77, 72, 64, 78, 70, 75, 65, 76, 71, 79, 69, 67, 196, 202, 201, 194, 205, 200, 192,
            206, 198, 203, 193, 204, 199, 207, 197, 195, 100, 106, 105, 98, 109, 104, 96, 110, 102,
            107, 97, 108, 103, 111, 101, 99, 212, 218, 217, 210, 221, 216, 208, 222, 214, 219, 209,
            220, 215, 223, 213, 211, 244, 250, 249, 242, 253, 248, 240, 254, 246, 251, 241, 252,
            247, 255, 245, 243, 164, 170, 169, 162, 173, 168, 160, 174, 166, 171, 161, 172, 167,
            175, 165, 163, 36, 42, 41, 34, 45, 40, 32, 46, 38, 43, 33, 44, 39, 47, 37, 35, 52, 58,
            57, 50, 61, 56, 48, 62, 54, 59, 49, 60, 55, 63, 53, 51, 132, 138, 137, 130, 141, 136,
            128, 142, 134, 139, 129, 140, 135, 143, 133, 131, 20, 26, 25, 18, 29, 24, 16, 30, 22,
            27, 17, 28, 23, 31, 21, 19, 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3, 116,
            122, 121, 114, 125, 120, 112, 126, 118, 123, 113, 124, 119, 127, 117, 115, 84, 90, 89,
            82, 93, 88, 80, 94, 86, 91, 81, 92, 87, 95, 85, 83, 148, 154, 153, 146, 157, 152, 144,
            158, 150, 155, 145, 156, 151, 159, 149, 147,
        ],
        [
            117, 120, 113, 125, 122, 115, 116, 114, 126, 127, 124, 119, 118, 112, 121, 123, 213,
            216, 209, 221, 218, 211, 212, 210, 222, 223, 220, 215, 214, 208, 217, 219, 165, 168,
            161, 173, 170, 163, 164, 162, 174, 175, 172, 167, 166, 160, 169, 171, 21, 24, 17, 29,
            26, 19, 20, 18, 30, 31, 28, 23, 22, 16, 25, 27, 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12,
            7, 6, 0, 9, 11, 133, 136, 129, 141, 138, 131, 132, 130, 142, 143, 140, 135, 134, 128,
            137, 139, 149, 152, 145, 157, 154, 147, 148, 146, 158, 159, 156, 151, 150, 144, 153,
            155, 245, 248, 241, 253, 250, 243, 244, 242, 254, 255, 252, 247, 246, 240, 249, 251,
            229, 232, 225, 237, 234, 227, 228, 226, 238, 239, 236, 231, 230, 224, 233, 235, 69, 72,
            65, 77, 74, 67, 68, 66, 78, 79, 76, 71, 70, 64, 73, 75, 101, 104, 97, 109, 106, 99,
            100, 98, 110, 111, 108, 103, 102, 96, 105, 107, 197, 200, 193, 205, 202, 195, 196, 194,
            206, 207, 204, 199, 198, 192, 201, 203, 181, 184, 177, 189, 186, 179, 180, 178, 190,
            191, 188, 183, 182, 176, 185, 187, 37, 40, 33, 45, 42, 35, 36, 34, 46, 47, 44, 39, 38,
            32, 41, 43, 85, 88, 81, 93, 90, 83, 84, 82, 94, 95, 92, 87, 86, 80, 89, 91, 53, 56, 49,
            61, 58, 51, 52, 50, 62, 63, 60, 55, 54, 48, 57, 59,
        ],
        [
            70, 76, 71, 65, 69, 79, 77, 72, 68, 74, 73, 78, 64, 67, 75, 66, 182, 188, 183, 177,
            181, 191, 189, 184, 180, 186, 185, 190, 176, 179, 187, 178, 166, 172, 167, 161, 165,
            175, 173, 168, 164, 170, 169, 174, 160, 163, 171, 162, 6, 12, 7, 1, 5, 15, 13, 8, 4,
            10, 9, 14, 0, 3, 11, 2, 118, 124, 119, 113, 117, 127, 125, 120, 116, 122, 121, 126,
            112, 115, 123, 114, 38, 44, 39, 33, 37, 47, 45, 40, 36, 42, 41, 46, 32, 35, 43, 34, 22,
            28, 23, 17, 21, 31, 29, 24, 20, 26, 25, 30, 16, 19, 27, 18, 214, 220, 215, 209, 213,
            223, 221, 216, 212, 218, 217, 222, 208, 211, 219, 210, 54, 60, 55, 49, 53, 63, 61, 56,
            52, 58, 57, 62, 48, 51, 59, 50, 102, 108, 103, 97, 101, 111, 109, 104, 100, 106, 105,
            110, 96, 99, 107, 98, 134, 140, 135, 129, 133, 143, 141, 136, 132, 138, 137, 142, 128,
            131, 139, 130, 86, 92, 87, 81, 85, 95, 93, 88, 84, 90, 89, 94, 80, 83, 91, 82, 150,
            156, 151, 145, 149, 159, 157, 152, 148, 154, 153, 158, 144, 147, 155, 146, 198, 204,
            199, 193, 197, 207, 205, 200, 196, 202, 201, 206, 192, 195, 203, 194, 246, 252, 247,
            241, 245, 255, 253, 248, 244, 250, 249, 254, 240, 243, 251, 242, 230, 236, 231, 225,
            229, 239, 237, 232, 228, 234, 233, 238, 224, 227, 235, 226,
        ],
        [
            29, 27, 20, 17, 19, 31, 21, 25, 16, 26, 30, 23, 22, 24, 18, 28, 253, 251, 244, 241,
            243, 255, 245, 249, 240, 250, 254, 247, 246, 248, 242, 252, 221, 219, 212, 209, 211,
            223, 213, 217, 208, 218, 222, 215, 214, 216, 210, 220, 13, 11, 4, 1, 3, 15, 5, 9, 0,
            10, 14, 7, 6, 8, 2, 12, 93, 91, 84, 81, 83, 95, 85, 89, 80, 90, 94, 87, 86, 88, 82, 92,
            125, 123, 116, 113, 115, 127, 117, 121, 112, 122, 126, 119, 118, 120, 114, 124, 173,
            171, 164, 161, 163, 175, 165, 169, 160, 170, 174, 167, 166, 168, 162, 172, 77, 75, 68,
            65, 67, 79, 69, 73, 64, 74, 78, 71, 70, 72, 66, 76, 157, 155, 148, 145, 147, 159, 149,
            153, 144, 154, 158, 151, 150, 152, 146, 156, 45, 43, 36, 33, 35, 47, 37, 41, 32, 42,
            46, 39, 38, 40, 34, 44, 61, 59, 52, 49, 51, 63, 53, 57, 48, 58, 62, 55, 54, 56, 50, 60,
            237, 235, 228, 225, 227, 239, 229, 233, 224, 234, 238, 231, 230, 232, 226, 236, 109,
            107, 100, 97, 99, 111, 101, 105, 96, 106, 110, 103, 102, 104, 98, 108, 189, 187, 180,
            177, 179, 191, 181, 185, 176, 186, 190, 183, 182, 184, 178, 188, 141, 139, 132, 129,
            131, 143, 133, 137, 128, 138, 142, 135, 134, 136, 130, 140, 205, 203, 196, 193, 195,
            207, 197, 201, 192, 202, 206, 199, 198, 200, 194, 204,
        ],
    ];

    const SBOX: SmallSbox = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    ];
}

pub enum CryptoProA {}

impl Sbox for CryptoProA {
    const EXP_SBOX: ExpSbox = [
        [
            57, 54, 51, 50, 56, 59, 49, 55, 58, 52, 62, 63, 60, 48, 61, 53, 121, 118, 115, 114,
            120, 123, 113, 119, 122, 116, 126, 127, 124, 112, 125, 117, 233, 230, 227, 226, 232,
            235, 225, 231, 234, 228, 238, 239, 236, 224, 237, 229, 153, 150, 147, 146, 152, 155,
            145, 151, 154, 148, 158, 159, 156, 144, 157, 149, 137, 134, 131, 130, 136, 139, 129,
            135, 138, 132, 142, 143, 140, 128, 141, 133, 169, 166, 163, 162, 168, 171, 161, 167,
            170, 164, 174, 175, 172, 160, 173, 165, 249, 246, 243, 242, 248, 251, 241, 247, 250,
            244, 254, 255, 252, 240, 253, 245, 9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13,
            5, 89, 86, 83, 82, 88, 91, 81, 87, 90, 84, 94, 95, 92, 80, 93, 85, 41, 38, 35, 34, 40,
            43, 33, 39, 42, 36, 46, 47, 44, 32, 45, 37, 105, 102, 99, 98, 104, 107, 97, 103, 106,
            100, 110, 111, 108, 96, 109, 101, 201, 198, 195, 194, 200, 203, 193, 199, 202, 196,
            206, 207, 204, 192, 205, 197, 185, 182, 179, 178, 184, 187, 177, 183, 186, 180, 190,
            191, 188, 176, 189, 181, 73, 70, 67, 66, 72, 75, 65, 71, 74, 68, 78, 79, 76, 64, 77,
            69, 217, 214, 211, 210, 216, 219, 209, 215, 218, 212, 222, 223, 220, 208, 221, 213, 25,
            22, 19, 18, 24, 27, 17, 23, 26, 20, 30, 31, 28, 16, 29, 21,
        ],
        [
            238, 228, 230, 226, 235, 227, 237, 232, 236, 239, 229, 234, 224, 231, 225, 233, 126,
            116, 118, 114, 123, 115, 125, 120, 124, 127, 117, 122, 112, 119, 113, 121, 174, 164,
            166, 162, 171, 163, 173, 168, 172, 175, 165, 170, 160, 167, 161, 169, 206, 196, 198,
            194, 203, 195, 205, 200, 204, 207, 197, 202, 192, 199, 193, 201, 222, 212, 214, 210,
            219, 211, 221, 216, 220, 223, 213, 218, 208, 215, 209, 217, 30, 20, 22, 18, 27, 19, 29,
            24, 28, 31, 21, 26, 16, 23, 17, 25, 62, 52, 54, 50, 59, 51, 61, 56, 60, 63, 53, 58, 48,
            55, 49, 57, 158, 148, 150, 146, 155, 147, 157, 152, 156, 159, 149, 154, 144, 151, 145,
            153, 14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9, 46, 36, 38, 34, 43, 35, 45,
            40, 44, 47, 37, 42, 32, 39, 33, 41, 190, 180, 182, 178, 187, 179, 189, 184, 188, 191,
            181, 186, 176, 183, 177, 185, 78, 68, 70, 66, 75, 67, 77, 72, 76, 79, 69, 74, 64, 71,
            65, 73, 254, 244, 246, 242, 251, 243, 253, 248, 252, 255, 245, 250, 240, 247, 241, 249,
            142, 132, 134, 130, 139, 131, 141, 136, 140, 143, 133, 138, 128, 135, 129, 137, 94, 84,
            86, 82, 91, 83, 93, 88, 92, 95, 85, 90, 80, 87, 81, 89, 110, 100, 102, 98, 107, 99,
            109, 104, 108, 111, 101, 106, 96, 103, 97, 105,
        ],
        [
            59, 53, 49, 57, 56, 61, 63, 48, 62, 52, 50, 51, 60, 55, 58, 54, 171, 165, 161, 169,
            168, 173, 175, 160, 174, 164, 162, 163, 172, 167, 170, 166, 219, 213, 209, 217, 216,
            221, 223, 208, 222, 212, 210, 211, 220, 215, 218, 214, 203, 197, 193, 201, 200, 205,
            207, 192, 206, 196, 194, 195, 204, 199, 202, 198, 27, 21, 17, 25, 24, 29, 31, 16, 30,
            20, 18, 19, 28, 23, 26, 22, 43, 37, 33, 41, 40, 45, 47, 32, 46, 36, 34, 35, 44, 39, 42,
            38, 11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6, 187, 181, 177, 185, 184, 189,
            191, 176, 190, 180, 178, 179, 188, 183, 186, 182, 123, 117, 113, 121, 120, 125, 127,
            112, 126, 116, 114, 115, 124, 119, 122, 118, 91, 85, 81, 89, 88, 93, 95, 80, 94, 84,
            82, 83, 92, 87, 90, 86, 155, 149, 145, 153, 152, 157, 159, 144, 158, 148, 146, 147,
            156, 151, 154, 150, 75, 69, 65, 73, 72, 77, 79, 64, 78, 68, 66, 67, 76, 71, 74, 70,
            139, 133, 129, 137, 136, 141, 143, 128, 142, 132, 130, 131, 140, 135, 138, 134, 251,
            245, 241, 249, 248, 253, 255, 240, 254, 244, 242, 243, 252, 247, 250, 246, 235, 229,
            225, 233, 232, 237, 239, 224, 238, 228, 226, 227, 236, 231, 234, 230, 107, 101, 97,
            105, 104, 109, 111, 96, 110, 100, 98, 99, 108, 103, 106, 102,
        ],
        [
            177, 189, 178, 185, 183, 186, 182, 176, 184, 188, 180, 181, 191, 179, 187, 190, 161,
            173, 162, 169, 167, 170, 166, 160, 168, 172, 164, 165, 175, 163, 171, 174, 241, 253,
            242, 249, 247, 250, 246, 240, 248, 252, 244, 245, 255, 243, 251, 254, 81, 93, 82, 89,
            87, 90, 86, 80, 88, 92, 84, 85, 95, 83, 91, 94, 1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5,
            15, 3, 11, 14, 193, 205, 194, 201, 199, 202, 198, 192, 200, 204, 196, 197, 207, 195,
            203, 206, 225, 237, 226, 233, 231, 234, 230, 224, 232, 236, 228, 229, 239, 227, 235,
            238, 129, 141, 130, 137, 135, 138, 134, 128, 136, 140, 132, 133, 143, 131, 139, 142,
            97, 109, 98, 105, 103, 106, 102, 96, 104, 108, 100, 101, 111, 99, 107, 110, 33, 45, 34,
            41, 39, 42, 38, 32, 40, 44, 36, 37, 47, 35, 43, 46, 49, 61, 50, 57, 55, 58, 54, 48, 56,
            60, 52, 53, 63, 51, 59, 62, 145, 157, 146, 153, 151, 154, 150, 144, 152, 156, 148, 149,
            159, 147, 155, 158, 17, 29, 18, 25, 23, 26, 22, 16, 24, 28, 20, 21, 31, 19, 27, 30,
            113, 125, 114, 121, 119, 122, 118, 112, 120, 124, 116, 117, 127, 115, 123, 126, 209,
            221, 210, 217, 215, 218, 214, 208, 216, 220, 212, 213, 223, 211, 219, 222, 65, 77, 66,
            73, 71, 74, 70, 64, 72, 76, 68, 69, 79, 67, 75, 78,
        ],
    ];

    const SBOX: SmallSbox = [
        [9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5],
        [3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1],
        [14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9],
        [14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6],
        [11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6],
        [3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6],
        [1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14],
        [11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4],
    ];
}

pub enum CryptoProB {}

impl Sbox for CryptoProB {
    const EXP_SBOX: ExpSbox = [
        [
            8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15, 24, 20, 27, 17, 19, 21, 16, 25,
            18, 30, 26, 28, 29, 22, 23, 31, 40, 36, 43, 33, 35, 37, 32, 41, 34, 46, 42, 44, 45, 38,
            39, 47, 168, 164, 171, 161, 163, 165, 160, 169, 162, 174, 170, 172, 173, 166, 167, 175,
            72, 68, 75, 65, 67, 69, 64, 73, 66, 78, 74, 76, 77, 70, 71, 79, 216, 212, 219, 209,
            211, 213, 208, 217, 210, 222, 218, 220, 221, 214, 215, 223, 88, 84, 91, 81, 83, 85, 80,
            89, 82, 94, 90, 92, 93, 86, 87, 95, 200, 196, 203, 193, 195, 197, 192, 201, 194, 206,
            202, 204, 205, 198, 199, 207, 152, 148, 155, 145, 147, 149, 144, 153, 146, 158, 154,
            156, 157, 150, 151, 159, 120, 116, 123, 113, 115, 117, 112, 121, 114, 126, 122, 124,
            125, 118, 119, 127, 56, 52, 59, 49, 51, 53, 48, 57, 50, 62, 58, 60, 61, 54, 55, 63,
            248, 244, 251, 241, 243, 245, 240, 249, 242, 254, 250, 252, 253, 246, 247, 255, 184,
            180, 187, 177, 179, 181, 176, 185, 178, 190, 186, 188, 189, 182, 183, 191, 136, 132,
            139, 129, 131, 133, 128, 137, 130, 142, 138, 140, 141, 134, 135, 143, 104, 100, 107,
            97, 99, 101, 96, 105, 98, 110, 106, 108, 109, 102, 103, 111, 232, 228, 235, 225, 227,
            229, 224, 233, 226, 238, 234, 236, 237, 230, 231, 239,
        ],
        [
            126, 124, 112, 122, 121, 114, 125, 123, 119, 117, 120, 127, 115, 118, 113, 116, 94, 92,
            80, 90, 89, 82, 93, 91, 87, 85, 88, 95, 83, 86, 81, 84, 14, 12, 0, 10, 9, 2, 13, 11, 7,
            5, 8, 15, 3, 6, 1, 4, 222, 220, 208, 218, 217, 210, 221, 219, 215, 213, 216, 223, 211,
            214, 209, 212, 190, 188, 176, 186, 185, 178, 189, 187, 183, 181, 184, 191, 179, 182,
            177, 180, 110, 108, 96, 106, 105, 98, 109, 107, 103, 101, 104, 111, 99, 102, 97, 100,
            30, 28, 16, 26, 25, 18, 29, 27, 23, 21, 24, 31, 19, 22, 17, 20, 46, 44, 32, 42, 41, 34,
            45, 43, 39, 37, 40, 47, 35, 38, 33, 36, 62, 60, 48, 58, 57, 50, 61, 59, 55, 53, 56, 63,
            51, 54, 49, 52, 174, 172, 160, 170, 169, 162, 173, 171, 167, 165, 168, 175, 163, 166,
            161, 164, 206, 204, 192, 202, 201, 194, 205, 203, 199, 197, 200, 207, 195, 198, 193,
            196, 254, 252, 240, 250, 249, 242, 253, 251, 247, 245, 248, 255, 243, 246, 241, 244,
            78, 76, 64, 74, 73, 66, 77, 75, 71, 69, 72, 79, 67, 70, 65, 68, 238, 236, 224, 234,
            233, 226, 237, 235, 231, 229, 232, 239, 227, 230, 225, 228, 158, 156, 144, 154, 153,
            146, 157, 155, 151, 149, 152, 159, 147, 150, 145, 148, 142, 140, 128, 138, 137, 130,
            141, 139, 135, 133, 136, 143, 131, 134, 129, 132,
        ],
        [
            130, 135, 140, 143, 137, 133, 138, 139, 129, 132, 128, 141, 134, 136, 142, 131, 50, 55,
            60, 63, 57, 53, 58, 59, 49, 52, 48, 61, 54, 56, 62, 51, 34, 39, 44, 47, 41, 37, 42, 43,
            33, 36, 32, 45, 38, 40, 46, 35, 98, 103, 108, 111, 105, 101, 106, 107, 97, 100, 96,
            109, 102, 104, 110, 99, 66, 71, 76, 79, 73, 69, 74, 75, 65, 68, 64, 77, 70, 72, 78, 67,
            210, 215, 220, 223, 217, 213, 218, 219, 209, 212, 208, 221, 214, 216, 222, 211, 226,
            231, 236, 239, 233, 229, 234, 235, 225, 228, 224, 237, 230, 232, 238, 227, 178, 183,
            188, 191, 185, 181, 186, 187, 177, 180, 176, 189, 182, 184, 190, 179, 194, 199, 204,
            207, 201, 197, 202, 203, 193, 196, 192, 205, 198, 200, 206, 195, 18, 23, 28, 31, 25,
            21, 26, 27, 17, 20, 16, 29, 22, 24, 30, 19, 114, 119, 124, 127, 121, 117, 122, 123,
            113, 116, 112, 125, 118, 120, 126, 115, 242, 247, 252, 255, 249, 245, 250, 251, 241,
            244, 240, 253, 246, 248, 254, 243, 162, 167, 172, 175, 169, 165, 170, 171, 161, 164,
            160, 173, 166, 168, 174, 163, 2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3,
            146, 151, 156, 159, 153, 149, 154, 155, 145, 148, 144, 157, 150, 152, 158, 147, 82, 87,
            92, 95, 89, 85, 90, 91, 81, 84, 80, 93, 86, 88, 94, 83,
        ],
        [
            5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14, 69, 66, 74, 75, 73, 65, 76, 67,
            71, 68, 77, 64, 70, 79, 72, 78, 181, 178, 186, 187, 185, 177, 188, 179, 183, 180, 189,
            176, 182, 191, 184, 190, 229, 226, 234, 235, 233, 225, 236, 227, 231, 228, 237, 224,
            230, 239, 232, 238, 133, 130, 138, 139, 137, 129, 140, 131, 135, 132, 141, 128, 134,
            143, 136, 142, 53, 50, 58, 59, 57, 49, 60, 51, 55, 52, 61, 48, 54, 63, 56, 62, 117,
            114, 122, 123, 121, 113, 124, 115, 119, 116, 125, 112, 118, 127, 120, 126, 21, 18, 26,
            27, 25, 17, 28, 19, 23, 20, 29, 16, 22, 31, 24, 30, 165, 162, 170, 171, 169, 161, 172,
            163, 167, 164, 173, 160, 166, 175, 168, 174, 37, 34, 42, 43, 41, 33, 44, 35, 39, 36,
            45, 32, 38, 47, 40, 46, 149, 146, 154, 155, 153, 145, 156, 147, 151, 148, 157, 144,
            150, 159, 152, 158, 101, 98, 106, 107, 105, 97, 108, 99, 103, 100, 109, 96, 102, 111,
            104, 110, 245, 242, 250, 251, 249, 241, 252, 243, 247, 244, 253, 240, 246, 255, 248,
            254, 213, 210, 218, 219, 217, 209, 220, 211, 215, 212, 221, 208, 214, 223, 216, 222,
            85, 82, 90, 91, 89, 81, 92, 83, 87, 84, 93, 80, 86, 95, 88, 94, 197, 194, 202, 203,
            201, 193, 204, 195, 199, 196, 205, 192, 198, 207, 200, 206,
        ],
    ];

    const SBOX: SmallSbox = [
        [8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15],
        [0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14],
        [14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4],
        [7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8],
        [2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3],
        [8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5],
        [5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14],
        [0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12],
    ];
}

pub enum CryptoProC {}

impl Sbox for CryptoProC {
    const EXP_SBOX: ExpSbox = [
        [
            1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3, 17, 27, 28, 18, 25, 29, 16, 31,
            20, 21, 24, 30, 26, 23, 22, 19, 113, 123, 124, 114, 121, 125, 112, 127, 116, 117, 120,
            126, 122, 119, 118, 115, 209, 219, 220, 210, 217, 221, 208, 223, 212, 213, 216, 222,
            218, 215, 214, 211, 177, 187, 188, 178, 185, 189, 176, 191, 180, 181, 184, 190, 186,
            183, 182, 179, 65, 75, 76, 66, 73, 77, 64, 79, 68, 69, 72, 78, 74, 71, 70, 67, 81, 91,
            92, 82, 89, 93, 80, 95, 84, 85, 88, 94, 90, 87, 86, 83, 33, 43, 44, 34, 41, 45, 32, 47,
            36, 37, 40, 46, 42, 39, 38, 35, 129, 139, 140, 130, 137, 141, 128, 143, 132, 133, 136,
            142, 138, 135, 134, 131, 225, 235, 236, 226, 233, 237, 224, 239, 228, 229, 232, 238,
            234, 231, 230, 227, 241, 251, 252, 242, 249, 253, 240, 255, 244, 245, 248, 254, 250,
            247, 246, 243, 193, 203, 204, 194, 201, 205, 192, 207, 196, 197, 200, 206, 202, 199,
            198, 195, 145, 155, 156, 146, 153, 157, 144, 159, 148, 149, 152, 158, 154, 151, 150,
            147, 161, 171, 172, 162, 169, 173, 160, 175, 164, 165, 168, 174, 170, 167, 166, 163,
            97, 107, 108, 98, 105, 109, 96, 111, 100, 101, 104, 110, 106, 103, 102, 99, 49, 59, 60,
            50, 57, 61, 48, 63, 52, 53, 56, 62, 58, 55, 54, 51,
        ],
        [
            56, 50, 53, 48, 52, 57, 63, 58, 51, 55, 60, 61, 54, 62, 49, 59, 104, 98, 101, 96, 100,
            105, 111, 106, 99, 103, 108, 109, 102, 110, 97, 107, 8, 2, 5, 0, 4, 9, 15, 10, 3, 7,
            12, 13, 6, 14, 1, 11, 24, 18, 21, 16, 20, 25, 31, 26, 19, 23, 28, 29, 22, 30, 17, 27,
            88, 82, 85, 80, 84, 89, 95, 90, 83, 87, 92, 93, 86, 94, 81, 91, 216, 210, 213, 208,
            212, 217, 223, 218, 211, 215, 220, 221, 214, 222, 209, 219, 168, 162, 165, 160, 164,
            169, 175, 170, 163, 167, 172, 173, 166, 174, 161, 171, 136, 130, 133, 128, 132, 137,
            143, 138, 131, 135, 140, 141, 134, 142, 129, 139, 184, 178, 181, 176, 180, 185, 191,
            186, 179, 183, 188, 189, 182, 190, 177, 187, 40, 34, 37, 32, 36, 41, 47, 42, 35, 39,
            44, 45, 38, 46, 33, 43, 152, 146, 149, 144, 148, 153, 159, 154, 147, 151, 156, 157,
            150, 158, 145, 155, 120, 114, 117, 112, 116, 121, 127, 122, 115, 119, 124, 125, 118,
            126, 113, 123, 232, 226, 229, 224, 228, 233, 239, 234, 227, 231, 236, 237, 230, 238,
            225, 235, 248, 242, 245, 240, 244, 249, 255, 250, 243, 247, 252, 253, 246, 254, 241,
            251, 200, 194, 197, 192, 196, 201, 207, 202, 195, 199, 204, 205, 198, 206, 193, 203,
            72, 66, 69, 64, 68, 73, 79, 74, 67, 71, 76, 77, 70, 78, 65, 75,
        ],
        [
            200, 205, 203, 192, 196, 197, 193, 194, 201, 195, 204, 206, 198, 207, 202, 199, 152,
            157, 155, 144, 148, 149, 145, 146, 153, 147, 156, 158, 150, 159, 154, 151, 184, 189,
            187, 176, 180, 181, 177, 178, 185, 179, 188, 190, 182, 191, 186, 183, 24, 29, 27, 16,
            20, 21, 17, 18, 25, 19, 28, 30, 22, 31, 26, 23, 136, 141, 139, 128, 132, 133, 129, 130,
            137, 131, 140, 142, 134, 143, 138, 135, 232, 237, 235, 224, 228, 229, 225, 226, 233,
            227, 236, 238, 230, 239, 234, 231, 40, 45, 43, 32, 36, 37, 33, 34, 41, 35, 44, 46, 38,
            47, 42, 39, 72, 77, 75, 64, 68, 69, 65, 66, 73, 67, 76, 78, 70, 79, 74, 71, 120, 125,
            123, 112, 116, 117, 113, 114, 121, 115, 124, 126, 118, 127, 122, 119, 56, 61, 59, 48,
            52, 53, 49, 50, 57, 51, 60, 62, 54, 63, 58, 55, 104, 109, 107, 96, 100, 101, 97, 98,
            105, 99, 108, 110, 102, 111, 106, 103, 88, 93, 91, 80, 84, 85, 81, 82, 89, 83, 92, 94,
            86, 95, 90, 87, 168, 173, 171, 160, 164, 165, 161, 162, 169, 163, 172, 174, 166, 175,
            170, 167, 8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7, 248, 253, 251, 240,
            244, 245, 241, 242, 249, 243, 252, 254, 246, 255, 250, 247, 216, 221, 219, 208, 212,
            213, 209, 210, 217, 211, 220, 222, 214, 223, 218, 215,
        ],
        [
            122, 121, 118, 120, 125, 126, 114, 112, 127, 115, 117, 123, 116, 113, 124, 119, 74, 73,
            70, 72, 77, 78, 66, 64, 79, 67, 69, 75, 68, 65, 76, 71, 10, 9, 6, 8, 13, 14, 2, 0, 15,
            3, 5, 11, 4, 1, 12, 7, 90, 89, 86, 88, 93, 94, 82, 80, 95, 83, 85, 91, 84, 81, 92, 87,
            170, 169, 166, 168, 173, 174, 162, 160, 175, 163, 165, 171, 164, 161, 172, 167, 42, 41,
            38, 40, 45, 46, 34, 32, 47, 35, 37, 43, 36, 33, 44, 39, 250, 249, 246, 248, 253, 254,
            242, 240, 255, 243, 245, 251, 244, 241, 252, 247, 234, 233, 230, 232, 237, 238, 226,
            224, 239, 227, 229, 235, 228, 225, 236, 231, 202, 201, 198, 200, 205, 206, 194, 192,
            207, 195, 197, 203, 196, 193, 204, 199, 106, 105, 102, 104, 109, 110, 98, 96, 111, 99,
            101, 107, 100, 97, 108, 103, 26, 25, 22, 24, 29, 30, 18, 16, 31, 19, 21, 27, 20, 17,
            28, 23, 186, 185, 182, 184, 189, 190, 178, 176, 191, 179, 181, 187, 180, 177, 188, 183,
            218, 217, 214, 216, 221, 222, 210, 208, 223, 211, 213, 219, 212, 209, 220, 215, 154,
            153, 150, 152, 157, 158, 146, 144, 159, 147, 149, 155, 148, 145, 156, 151, 58, 57, 54,
            56, 61, 62, 50, 48, 63, 51, 53, 59, 52, 49, 60, 55, 138, 137, 134, 136, 141, 142, 130,
            128, 143, 131, 133, 139, 132, 129, 140, 135,
        ],
    ];

    const SBOX: SmallSbox = [
        [1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3],
        [0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3],
        [8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11],
        [3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4],
        [8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7],
        [12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13],
        [10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7],
        [7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8],
    ];
}

pub enum CryptoProD {}

impl Sbox for CryptoProD {
    const EXP_SBOX: ExpSbox = [
        [
            90, 84, 85, 86, 88, 81, 83, 87, 93, 92, 94, 80, 89, 82, 91, 95, 250, 244, 245, 246,
            248, 241, 243, 247, 253, 252, 254, 240, 249, 242, 251, 255, 74, 68, 69, 70, 72, 65, 67,
            71, 77, 76, 78, 64, 73, 66, 75, 79, 10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11,
            15, 42, 36, 37, 38, 40, 33, 35, 39, 45, 44, 46, 32, 41, 34, 43, 47, 218, 212, 213, 214,
            216, 209, 211, 215, 221, 220, 222, 208, 217, 210, 219, 223, 186, 180, 181, 182, 184,
            177, 179, 183, 189, 188, 190, 176, 185, 178, 187, 191, 154, 148, 149, 150, 152, 145,
            147, 151, 157, 156, 158, 144, 153, 146, 155, 159, 26, 20, 21, 22, 24, 17, 19, 23, 29,
            28, 30, 16, 25, 18, 27, 31, 122, 116, 117, 118, 120, 113, 115, 119, 125, 124, 126, 112,
            121, 114, 123, 127, 106, 100, 101, 102, 104, 97, 99, 103, 109, 108, 110, 96, 105, 98,
            107, 111, 58, 52, 53, 54, 56, 49, 51, 55, 61, 60, 62, 48, 57, 50, 59, 63, 202, 196,
            197, 198, 200, 193, 195, 199, 205, 204, 206, 192, 201, 194, 203, 207, 234, 228, 229,
            230, 232, 225, 227, 231, 237, 236, 238, 224, 233, 226, 235, 239, 170, 164, 165, 166,
            168, 161, 163, 167, 173, 172, 174, 160, 169, 162, 171, 175, 138, 132, 133, 134, 136,
            129, 131, 135, 141, 140, 142, 128, 137, 130, 139, 143,
        ],
        [
            71, 79, 76, 78, 73, 68, 65, 64, 67, 75, 69, 66, 70, 74, 72, 77, 167, 175, 172, 174,
            169, 164, 161, 160, 163, 171, 165, 162, 166, 170, 168, 173, 119, 127, 124, 126, 121,
            116, 113, 112, 115, 123, 117, 114, 118, 122, 120, 125, 199, 207, 204, 206, 201, 196,
            193, 192, 195, 203, 197, 194, 198, 202, 200, 205, 7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5,
            2, 6, 10, 8, 13, 247, 255, 252, 254, 249, 244, 241, 240, 243, 251, 245, 242, 246, 250,
            248, 253, 39, 47, 44, 46, 41, 36, 33, 32, 35, 43, 37, 34, 38, 42, 40, 45, 135, 143,
            140, 142, 137, 132, 129, 128, 131, 139, 133, 130, 134, 138, 136, 141, 231, 239, 236,
            238, 233, 228, 225, 224, 227, 235, 229, 226, 230, 234, 232, 237, 23, 31, 28, 30, 25,
            20, 17, 16, 19, 27, 21, 18, 22, 26, 24, 29, 103, 111, 108, 110, 105, 100, 97, 96, 99,
            107, 101, 98, 102, 106, 104, 109, 87, 95, 92, 94, 89, 84, 81, 80, 83, 91, 85, 82, 86,
            90, 88, 93, 215, 223, 220, 222, 217, 212, 209, 208, 211, 219, 213, 210, 214, 218, 216,
            221, 183, 191, 188, 190, 185, 180, 177, 176, 179, 187, 181, 178, 182, 186, 184, 189,
            151, 159, 156, 158, 153, 148, 145, 144, 147, 155, 149, 146, 150, 154, 152, 157, 55, 63,
            60, 62, 57, 52, 49, 48, 51, 59, 53, 50, 54, 58, 56, 61,
        ],
        [
            119, 118, 116, 123, 121, 124, 114, 122, 113, 120, 112, 126, 127, 125, 115, 117, 103,
            102, 100, 107, 105, 108, 98, 106, 97, 104, 96, 110, 111, 109, 99, 101, 39, 38, 36, 43,
            41, 44, 34, 42, 33, 40, 32, 46, 47, 45, 35, 37, 71, 70, 68, 75, 73, 76, 66, 74, 65, 72,
            64, 78, 79, 77, 67, 69, 215, 214, 212, 219, 217, 220, 210, 218, 209, 216, 208, 222,
            223, 221, 211, 213, 151, 150, 148, 155, 153, 156, 146, 154, 145, 152, 144, 158, 159,
            157, 147, 149, 247, 246, 244, 251, 249, 252, 242, 250, 241, 248, 240, 254, 255, 253,
            243, 245, 7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5, 167, 166, 164, 171,
            169, 172, 162, 170, 161, 168, 160, 174, 175, 173, 163, 165, 23, 22, 20, 27, 25, 28, 18,
            26, 17, 24, 16, 30, 31, 29, 19, 21, 87, 86, 84, 91, 89, 92, 82, 90, 81, 88, 80, 94, 95,
            93, 83, 85, 183, 182, 180, 187, 185, 188, 178, 186, 177, 184, 176, 190, 191, 189, 179,
            181, 135, 134, 132, 139, 137, 140, 130, 138, 129, 136, 128, 142, 143, 141, 131, 133,
            231, 230, 228, 235, 233, 236, 226, 234, 225, 232, 224, 238, 239, 237, 227, 229, 199,
            198, 196, 203, 201, 204, 194, 202, 193, 200, 192, 206, 207, 205, 195, 197, 55, 54, 52,
            59, 57, 60, 50, 58, 49, 56, 48, 62, 63, 61, 51, 53,
        ],
        [
            29, 30, 20, 17, 23, 16, 21, 26, 19, 28, 24, 31, 22, 18, 25, 27, 61, 62, 52, 49, 55, 48,
            53, 58, 51, 60, 56, 63, 54, 50, 57, 59, 173, 174, 164, 161, 167, 160, 165, 170, 163,
            172, 168, 175, 166, 162, 169, 171, 157, 158, 148, 145, 151, 144, 149, 154, 147, 156,
            152, 159, 150, 146, 153, 155, 93, 94, 84, 81, 87, 80, 85, 90, 83, 92, 88, 95, 86, 82,
            89, 91, 189, 190, 180, 177, 183, 176, 181, 186, 179, 188, 184, 191, 182, 178, 185, 187,
            77, 78, 68, 65, 71, 64, 69, 74, 67, 76, 72, 79, 70, 66, 73, 75, 253, 254, 244, 241,
            247, 240, 245, 250, 243, 252, 248, 255, 246, 242, 249, 251, 141, 142, 132, 129, 135,
            128, 133, 138, 131, 140, 136, 143, 134, 130, 137, 139, 109, 110, 100, 97, 103, 96, 101,
            106, 99, 108, 104, 111, 102, 98, 105, 107, 125, 126, 116, 113, 119, 112, 117, 122, 115,
            124, 120, 127, 118, 114, 121, 123, 237, 238, 228, 225, 231, 224, 229, 234, 227, 236,
            232, 239, 230, 226, 233, 235, 221, 222, 212, 209, 215, 208, 213, 218, 211, 220, 216,
            223, 214, 210, 217, 219, 13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11, 45, 46,
            36, 33, 39, 32, 37, 42, 35, 44, 40, 47, 38, 34, 41, 43, 205, 206, 196, 193, 199, 192,
            197, 202, 195, 204, 200, 207, 198, 194, 201, 203,
        ],
    ];

    const SBOX: SmallSbox = [
        [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
        [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
        [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
        [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
        [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
        [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
        [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
        [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sbox<S: Sbox>() {
        let gen_sbox = S::gen_exp_sbox();
        for i in 0..4 {
            for j in 0..256 {
                assert_eq!(gen_sbox[i][j], S::EXP_SBOX[i][j]);
            }
        }
    }

    #[test]
    fn test_sboxes() {
        test_sbox::<Tc26>();
        test_sbox::<TestSbox>();
        test_sbox::<CryptoProA>();
        test_sbox::<CryptoProB>();
        test_sbox::<CryptoProC>();
        test_sbox::<CryptoProD>();
    }
}
