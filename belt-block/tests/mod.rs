#[cfg(feature = "cipher")]
use belt_block::BeltBlock;
#[cfg(feature = "cipher")]
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;

fn get_u32(block: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(block[4 * i..][..4].try_into().unwrap())
}

/// Example vectors from STB 34.101.31 (2020):
/// http://apmi.bsu.by/assets/files/std/belt-spec371.pdf
#[test]
fn belt_block() {
    // Table A.1
    let key1 = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let pt1 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");
    let ct1 = hex!("69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E");
    // Table A.2
    let key2 = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
    let pt2 = hex!("0DC53006 00CAB840 B38448E5 E993F421");
    let ct2 = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1");

    for (key, pt, ct) in [(key1, pt1, ct1), (key2, pt2, ct2)] {
        let mut k = [0u32; 8];
        for i in 0..8 {
            k[i] = get_u32(&key, i);
        }
        let mut x = [0u32; 4];
        for i in 0..4 {
            x[i] = get_u32(&pt, i);
        }
        let mut y = [0u32; 4];
        for i in 0..4 {
            y[i] = get_u32(&ct, i);
        }

        let res = belt_block::belt_block_raw(x, &k);
        assert_eq!(res, y);

        #[cfg(feature = "cipher")]
        {
            let cipher = BeltBlock::new(&key.into());
            let mut block = pt.into();
            cipher.encrypt_block(&mut block);
            assert_eq!(block, ct.into());
            cipher.decrypt_block(&mut block);
            assert_eq!(block, pt.into());
        }
    }
}

#[test]
fn stb_34_101_31_a6() {
    let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let mut x1 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
    let y1 = hex!("49A38EE1 08D6C742 E52B774F 00A6EF98 B106CBD1 3EA4FB06 80323051 BC04DF76 E487B055 C69BCF54 1176169F 1DC9F6C8");

    let mut x2 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B89");
    let y2 = hex!("F08EF22D CAA06C81 FB127219 74221CA7 AB82C628 56FCF2F9 FCA006E0 19A28F16 E5821A51 F5735946 25DBAB8F 6A5C94");

    #[cfg(feature = "cipher")]
    {
        let belt = BeltBlock::new_from_slice(&k).unwrap();

        let x_bkp = x1;

        belt.wblock_enc(&mut x1);
        assert_eq!(x1, y1);
        belt.wblock_dec(&mut x1);
        assert_eq!(x1, x_bkp);

        let x_bkp = x2;
        belt.wblock_enc(&mut x2);
        assert_eq!(x2, y2);
        belt.wblock_dec(&mut x2);
        assert_eq!(x2, x_bkp);
    }
}

#[test]
fn stb_34_101_31_a7() {
    let k = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
    let mut y1 = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B 637C306A DD4EA779 9EB23D31");
    let x1 = hex!("92632EE0 C21AD9E0 9A39343E 5C07DAA4 889B03F2 E6847EB1 52EC99F7 A4D9F154 B5EF68D8 E4A39E56 7153DE13 D72254EE");

    let mut y2 =
        hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B");
    let x2 =
        hex!("DF3F8822 30BAAFFC 92F05660 32117231 0E3CB218 2681EF43 102E6717 5E177BD7 5E93E4E8");

    let belt = BeltBlock::new_from_slice(&k).unwrap();

    let y_bkp = y1;

    #[cfg(feature = "cipher")]
    {
        belt.wblock_dec(&mut y1);
        assert_eq!(y1, x1);
        belt.wblock_enc(&mut y1);
        assert_eq!(y1, y_bkp);

        let y_bkp = y2;
        belt.wblock_dec(&mut y2);
        assert_eq!(y2, x2);
        belt.wblock_enc(&mut y2);
        assert_eq!(y2, y_bkp);
    }
}
