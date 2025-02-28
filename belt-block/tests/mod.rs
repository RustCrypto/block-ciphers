//! Example vectors from STB 34.101.31 (2020):
//! http://apmi.bsu.by/assets/files/std/belt-spec371.pdf
#[cfg(feature = "cipher")]
use belt_block::{
    BeltBlock,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use belt_block::{belt_block_raw, belt_wblock_dec, belt_wblock_enc};
use hex_literal::hex;

#[test]
fn belt_block() {
    // Table A.1
    let key1 = hex!(
        "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647"
        "06075316 ED247A37 39CBA383 03A98BF6"
    );
    let pt1 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");
    let ct1 = hex!("69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E");
    // Table A.2
    let key2 = hex!(
        "92BD9B1C E5D14101 5445FBC9 5E4D0EF2"
        "682080AA 227D642F 2687F934 90405511"
    );
    let pt2 = hex!("0DC53006 00CAB840 B38448E5 E993F421");
    let ct2 = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1");

    for (key, pt, ct) in [(key1, pt1, ct1), (key2, pt2, ct2)] {
        let res = belt_block_raw(to_u32(&pt), &to_u32(&key));
        assert_eq!(res, to_u32(&ct));

        #[cfg(feature = "cipher")]
        {
            let cipher = BeltBlock::new(&key.into());
            let mut block = pt.into();
            cipher.encrypt_block(&mut block);
            assert_eq!(block, ct);
            cipher.decrypt_block(&mut block);
            assert_eq!(block, pt);
        }
    }
}

#[test]
fn belt_wblock() {
    // Table A.6
    let k1 = hex!(
        "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647"
        "06075316 ED247A37 39CBA383 03A98BF6"
    );
    let x1 = hex!(
        "B194BAC8 0A08F53B 366D008E 584A5DE4"
        "8504FA9D 1BB6C7AC 252E72C2 02FDCE0D"
        "5BE3D612 17B96181 FE6786AD 716B890B"
    );
    let y1 = hex!(
        "49A38EE1 08D6C742 E52B774F 00A6EF98"
        "B106CBD1 3EA4FB06 80323051 BC04DF76"
        "E487B055 C69BCF54 1176169F 1DC9F6C8"
    );
    let x2 = hex!(
        "B194BAC8 0A08F53B 366D008E 584A5DE4"
        "8504FA9D 1BB6C7AC 252E72C2 02FDCE0D"
        "5BE3D612 17B96181 FE6786AD 716B89"
    );
    let y2 = hex!(
        "F08EF22D CAA06C81 FB127219 74221CA7"
        "AB82C628 56FCF2F9 FCA006E0 19A28F16"
        "E5821A51 F5735946 25DBAB8F 6A5C94"
    );

    // Table A.7
    let k2 = hex!(
        "92BD9B1C E5D14101 5445FBC9 5E4D0EF2"
        "682080AA 227D642F 2687F934 90405511"
    );
    let y3 = hex!(
        "E12BDC1A E28257EC 703FCCF0 95EE8DF1"
        "C1AB7638 9FE678CA F7C6F860 D5BB9C4F"
        "F33C657B 637C306A DD4EA779 9EB23D31"
    );
    let x3 = hex!(
        "92632EE0 C21AD9E0 9A39343E 5C07DAA4"
        "889B03F2 E6847EB1 52EC99F7 A4D9F154"
        "B5EF68D8 E4A39E56 7153DE13 D72254EE"
    );
    let x4 = hex!(
        "DF3F8822 30BAAFFC 92F05660 32117231"
        "0E3CB218 2681EF43 102E6717 5E177BD7"
        "5E93E4E8"
    );
    let y4 = hex!(
        "E12BDC1A E28257EC 703FCCF0 95EE8DF1"
        "C1AB7638 9FE678CA F7C6F860 D5BB9C4F"
        "F33C657B"
    );

    let tests = [
        (k1, &x1[..], &y1[..]),
        (k1, &x2[..], &y2[..]),
        (k2, &x3[..], &y3[..]),
        (k2, &x4[..], &y4[..]),
    ];
    for (key, x, y) in tests {
        let k = to_u32(&key);
        let mut t = x.to_vec();
        belt_wblock_enc(&mut t, &k).unwrap();
        assert_eq!(t, y);
        belt_wblock_dec(&mut t, &k).unwrap();
        assert_eq!(t, x)
    }

    // synthetic round-trip tests
    let k = to_u32(&k1);
    let x: Vec<u8> = (0u8..255).collect();
    for i in 32..x.len() {
        let mut t = x[..i].to_vec();
        for _ in 0..16 {
            belt_wblock_enc(&mut t, &k).unwrap();
        }
        for _ in 0..16 {
            belt_wblock_dec(&mut t, &k).unwrap();
        }
        assert_eq!(t, x[..i]);
    }
}

fn to_u32<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    let mut res = [0u32; N];
    res.iter_mut()
        .zip(src.chunks_exact(4))
        .for_each(|(dst, src)| *dst = u32::from_le_bytes(src.try_into().unwrap()));
    res
}
