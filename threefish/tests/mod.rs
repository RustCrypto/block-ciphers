//! Test vectors from:
//! https://github.com/weidai11/cryptopp/blob/master/TestVectors/threefish.txt
#![cfg(feature = "cipher")]
use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;
use threefish::{Threefish256, Threefish512, Threefish1024};

struct Vector {
    key: &'static [u8],
    tweak: Option<&'static [u8]>,
    pt: &'static [u8],
    ct: &'static [u8],
}

macro_rules! impl_test {
    {$name:ident, $cipher:ty, $tests:expr,} => {
        #[test]
        #[allow(deprecated)] // uses `clone_from_slice`
        fn $name() {
            let vectors = $tests;
            for &Vector { key, tweak, pt, ct } in vectors.iter() {
                let cipher = match tweak {
                    Some(tweak) => {
                        let key = key.try_into().unwrap();
                        let tweak = tweak.try_into().unwrap();
                        <$cipher>::new_with_tweak(key, tweak)
                    }
                    None => <$cipher>::new_from_slice(key).unwrap(),
                };
                let mut t = Block::<$cipher>::clone_from_slice(pt);
                cipher.encrypt_block(&mut t);
                assert_eq!(t[..], ct[..]);
                cipher.decrypt_block(&mut t);
                assert_eq!(t[..], pt[..]);

                let mut t = [t; 64];
                cipher.encrypt_blocks(&mut t);
                assert!(t.iter().all(|b| b[..] == ct[..]));
                cipher.decrypt_blocks(&mut t);
                assert!(t.iter().all(|b| b[..] == pt[..]));
            }
        }
    };
}

impl_test! {
    threefish_256,
    Threefish256,
    [
        Vector {
            key: &[0; 32],
            tweak: None,
            pt: &[0; 32],
            ct: &hex!(
                "84DA2A1F8BEAEE94 7066AE3E3103F1AD"
                "536DB1F4A1192495 116B9F3CE6133FD8"
            ),
        },
        Vector {
            key: &hex!(
                "1011121314151617 18191A1B1C1D1E1F"
                "2021222324252627 28292A2B2C2D2E2F"
            ),
            tweak: Some(&hex!("0001020304050607 08090A0B0C0D0E0F")),
            pt: &hex!(
                "FFFEFDFCFBFAF9F8 F7F6F5F4F3F2F1F0"
                "EFEEEDECEBEAE9E8 E7E6E5E4E3E2E1E0"
            ),
            ct: &hex!(
                "E0D091FF0EEA8FDF C98192E62ED80AD5"
                "9D865D08588DF476 657056B5955E97DF"
            ),
        },
    ],
}

impl_test! {
    threefish_512,
    Threefish512,
    [
        Vector {
            key: &[0; 64],
            tweak: None,
            pt: &[0; 64],
            ct: &hex!(
                "B1A2BBC6EF6025BC 40EB3822161F36E3"
                "75D1BB0AEE3186FB D19E47C5D479947B"
                "7BC2F8586E35F0CF F7E7F03084B0B7B1"
                "F1AB3961A580A3E9 7EB41EA14A6D7BBE"
            ),
        },
        Vector {
            key: &hex!(
                "B1A2BBC6EF6025BC 40EB3822161F36E3"
                "75D1BB0AEE3186FB D19E47C5D479947B"
                "7BC2F8586E35F0CF F7E7F03084B0B7B1"
                "F1AB3961A580A3E9 7EB41EA14A6D7BBE"
            ),
            tweak: None,
            pt: &[0; 64],
            ct: &hex!(
                "F13CA06760DD9BBE AB87B6C56F3BBBDB"
                "E9D08A77978B942A C02D471DC10268F2"
                "261C3D4330D6CA34 1F4BD4115DEE16A2"
                "1DCDA2A34A0A76FB A976174E4CF1E306"
            ),
        },
        Vector {
            key: &hex!(
                "F13CA06760DD9BBE AB87B6C56F3BBBDB"
                "E9D08A77978B942A C02D471DC10268F2"
                "261C3D4330D6CA34 1F4BD4115DEE16A2"
                "1DCDA2A34A0A76FB A976174E4CF1E306"
            ),
            tweak: None,
            pt: &hex!(
                "B1A2BBC6EF6025BC 40EB3822161F36E3"
                "75D1BB0AEE3186FB D19E47C5D479947B"
                "7BC2F8586E35F0CF F7E7F03084B0B7B1"
                "F1AB3961A580A3E9 7EB41EA14A6D7BBE"
            ),
            ct: &hex!(
                "1BEC82CBA1357566 B34E1CF1FBF123A1"
                "41C8F4089F6E4CE3 209AEA10095AEC93"
                "C900D068BDC7F7A2 DD58513C11DEC956"
                "B93169B1C4F24CED E31A265DE83E36B4"
            ),
        },
        Vector {
            key: &hex!(
                "F13CA06760DD9BBE AB87B6C56F3BBBDB"
                "E9D08A77978B942A C02D471DC10268F2"
                "261C3D4330D6CA34 1F4BD4115DEE16A2"
                "1DCDA2A34A0A76FB A976174E4CF1E306"
            ),
            tweak: None,
            pt: &hex!(
                "B1A2BBC6EF6025BC 40EB3822161F36E3"
                "75D1BB0AEE3186FB D19E47C5D479947B"
                "7BC2F8586E35F0CF F7E7F03084B0B7B1"
                "F1AB3961A580A3E9 7EB41EA14A6D7BBF"
            ),
            ct: &hex!(
                "073CB5F8FABFA17D B751477F294EB3DD"
                "4ACD92B78397331F CC36A9C3D3055B81"
                "D867CBDD56279037 373359CA1832669A"
                "F4B87A1F2FDAF8D3 6E2FB7A6D19F5D45"
            ),
        },
        Vector {
            key: &[0; 64],
            tweak: None,
            pt: &[0; 64],
            ct: &hex!(
                "B1A2BBC6EF6025BC 40EB3822161F36E3"
                "75D1BB0AEE3186FB D19E47C5D479947B"
                "7BC2F8586E35F0CF F7E7F03084B0B7B1"
                "F1AB3961A580A3E9 7EB41EA14A6D7BBE"
            ),
        },
        Vector {
            key: &hex!(
                "1011121314151617 18191A1B1C1D1E1F"
                "2021222324252627 28292A2B2C2D2E2F"
                "3031323334353637 38393A3B3C3D3E3F"
                "4041424344454647 48494A4B4C4D4E4F"
            ),
            tweak: Some(&hex!("0001020304050607 08090A0B0C0D0E0F")),
            pt: &hex!(
                "FFFEFDFCFBFAF9F8 F7F6F5F4F3F2F1F0"
                "EFEEEDECEBEAE9E8 E7E6E5E4E3E2E1E0"
                "DFDEDDDCDBDAD9D8 D7D6D5D4D3D2D1D0"
                "CFCECDCCCBCAC9C8 C7C6C5C4C3C2C1C0"
            ),
            ct: &hex!(
                "E304439626D45A2C B401CAD8D636249A"
                "6338330EB06D45DD 8B36B90E97254779"
                "272A0A8D99463504 784420EA18C9A725"
                "AF11DFFEA1016234 8927673D5C1CAF3D"
            ),
        },
    ],
}

impl_test! {
    threefish_1024,
    Threefish1024,
    [
        Vector {
            key: &[0; 128],
            tweak: None,
            pt: &[0; 128],
            ct: &hex!(
                "F05C3D0A3D05B304 F785DDC7D1E03601"
                "5C8AA76E2F217B06 C6E1544C0BC1A90D"
                "F0ACCB9473C24E0F D54FEA68057F4332"
                "9CB454761D6DF5CF 7B2E9B3614FBD5A2"
                "0B2E4760B4060354 0D82EABC5482C171"
                "C832AFBE68406BC3 9500367A592943FA"
                "9A5B4A43286CA3C4 CF46104B443143D5"
                "60A4B230488311DF 4FEEF7E1DFE8391E"
            ),
        },
        Vector {
            key: &hex!(
                "1011121314151617 18191A1B1C1D1E1F"
                "2021222324252627 28292A2B2C2D2E2F"
                "3031323334353637 38393A3B3C3D3E3F"
                "4041424344454647 48494A4B4C4D4E4F"
                "5051525354555657 58595A5B5C5D5E5F"
                "6061626364656667 68696A6B6C6D6E6F"
                "7071727374757677 78797A7B7C7D7E7F"
                "8081828384858687 88898A8B8C8D8E8F"
            ),
            tweak: Some(&hex!("0001020304050607 08090A0B0C0D0E0F")),
            pt: &hex!(
                "FFFEFDFCFBFAF9F8 F7F6F5F4F3F2F1F0"
                "EFEEEDECEBEAE9E8 E7E6E5E4E3E2E1E0"
                "DFDEDDDCDBDAD9D8 D7D6D5D4D3D2D1D0"
                "CFCECDCCCBCAC9C8 C7C6C5C4C3C2C1C0"
                "BFBEBDBCBBBAB9B8 B7B6B5B4B3B2B1B0"
                "AFAEADACABAAA9A8 A7A6A5A4A3A2A1A0"
                "9F9E9D9C9B9A9998 9796959493929190"
                "8F8E8D8C8B8A8988 8786858483828180"
            ),
            ct: &hex!(
                "A6654DDBD73CC3B0 5DD777105AA849BC"
                "E49372EAAFFC5568 D254771BAB85531C"
                "94F780E7FFAAE430 D5D8AF8C70EEBBE1"
                "760F3B42B737A89C B363490D670314BD"
                "8AA41EE63C2E1F45 FBD477922F8360B3"
                "88D6125EA6C7AF0A D7056D01796E90C8"
                "3313F4150A5716B3 0ED5F569288AE974"
                "CE2B4347926FCE57 DE44512177DD7CDE"
            ),
        },
    ],
}
