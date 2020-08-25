//! Test vectors from GOST R 34.13-2015:
//! https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
use gost_modes::block_padding::ZeroPadding;
use gost_modes::consts::{U14, U16, U2, U3, U32, U5};
use gost_modes::generic_array::GenericArray;
use gost_modes::{BlockMode, NewStreamCipher, StreamCipher};
use gost_modes::{Ecb, GostCbc, GostCfb, GostCtr128, GostCtr64, GostOfb};
use hex_literal::hex;
use kuznyechik::Kuznyechik;
use magma::{block_cipher::NewBlockCipher, Magma};
use stream_cipher::new_seek_test;

fn test_stream_cipher(cipher: impl StreamCipher + Clone, pt: &[u8], ct: &[u8]) {
    let mut buf = pt.to_vec();
    cipher.clone().encrypt(&mut buf);
    assert_eq!(buf, &ct[..]);
    cipher.clone().decrypt(&mut buf);
    assert_eq!(buf, &pt[..]);

    for i in 1..32 {
        let mut c = cipher.clone();
        let mut buf = pt.to_vec();
        for chunk in buf.chunks_mut(i) {
            c.encrypt(chunk);
        }
        assert_eq!(buf, &ct[..]);

        let mut c = cipher.clone();
        for chunk in buf.chunks_mut(i) {
            c.decrypt(chunk);
        }
        assert_eq!(buf, &pt[..]);
    }
}

#[test]
#[rustfmt::skip]
fn kuznyechik_modes() {
    let key = GenericArray::from_slice(&hex!("
        8899aabbccddeeff0011223344556677
        fedcba98765432100123456789abcdef
    "));
    let iv = GenericArray::from_slice(&hex!("
        1234567890abcef0a1b2c3d4e5f00112
        23344556677889901213141516171819
    "));
    let ctr_iv = GenericArray::from_slice(&hex!("
        1234567890abcef0
    "));
    let pt = hex!("
        1122334455667700ffeeddccbbaa9988
        00112233445566778899aabbcceeff0a
        112233445566778899aabbcceeff0a00
        2233445566778899aabbcceeff0a0011
    ");
    let ecb_ct = hex!("
        7f679d90bebc24305a468d42b9d4edcd
        b429912c6e0032f9285452d76718d08b
        f0ca33549d247ceef3f5a5313bd4b157
        d0b09ccde830b9eb3a02c4c5aa8ada98
    ");
    let ctr_ct = hex!("
        f195d8bec10ed1dbd57b5fa240bda1b8
        85eee733f6a13e5df33ce4b33c45dee4
        a5eae88be6356ed3d5e877f13564a3a5
        cb91fab1f20cbab6d1c6d15820bdba73
    ");
    let ofb_ct = hex!("
        81800a59b1842b24ff1f795e897abd95
        ed5b47a7048cfab48fb521369d9326bf
        66a257ac3ca0b8b1c80fe7fc10288a13
        203ebbc066138660a0292243f6903150
    ");
    let cbc_ct = hex!("
        689972d4a085fa4d90e52e3d6d7dcc27
        2826e661b478eca6af1e8e448d5ea5ac
        fe7babf1e91999e85640e8b0f49d90d0
        167688065a895c631a2d9a1560b63970
    ");
    let cfb_ct = hex!("
        81800a59b1842b24ff1f795e897abd95
        ed5b47a7048cfab48fb521369d9326bf
        79f2a8eb5cc68d38842d264e97a238b5
        4ffebecd4e922de6c75bd9dd44fbf4d1
    ");

    let c = GostOfb::<Kuznyechik, U2>::new(&key, &iv);
    test_stream_cipher(c, &pt, &ofb_ct);

    let c = GostCfb::<Kuznyechik, U32>::new(&key, &iv);
    test_stream_cipher(c, &pt, &cfb_ct);

    let c = GostCtr128::<Kuznyechik>::new(&key, &ctr_iv);
    test_stream_cipher(c, &pt, &ctr_ct);

    type EcbCipher = Ecb<Kuznyechik, ZeroPadding>;
    let cipher = Kuznyechik::new(&key);
    let buf = EcbCipher::new(cipher, &Default::default()).encrypt_vec(&pt);
    assert_eq!(buf, &ecb_ct[..]);
    let buf = EcbCipher::new(cipher, &Default::default())
        .decrypt_vec(&ecb_ct)
        .unwrap();
    assert_eq!(buf, &pt[..]);

    type CbcCipher = GostCbc<Kuznyechik, ZeroPadding, U2>;
    let cipher = Kuznyechik::new(&key);
    let buf = CbcCipher::new(cipher, &iv).encrypt_vec(&pt);
    assert_eq!(buf, &cbc_ct[..]);
    let buf = CbcCipher::new(cipher, &iv).decrypt_vec(&cbc_ct).unwrap();
    assert_eq!(buf, &pt[..]);
}

#[test]
#[rustfmt::skip]
fn magma_modes() {
    let key = GenericArray::from_slice(&hex!("
        ffeeddccbbaa99887766554433221100
        f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    "));
    let iv = GenericArray::from_slice(&hex!("
        1234567890abcdef234567890abcdef1
    "));
    let ctr_iv = GenericArray::from_slice(&hex!("
        12345678
    "));
    let cbc_iv = GenericArray::from_slice(&hex!("
        1234567890abcdef234567890abcdef134567890abcdef12
    "));
    let pt = hex!("
        92def06b3c130a59db54c704f8189d20
        4a98fb2e67a8024c8912409b17b57e41
    ");
    let ecb_ct = hex!("
        2b073f0494f372a0de70e715d3556e48
        11d8d9e9eacfbc1e7c68260996c67efb
    ");
    let ctr_ct = hex!("
        4e98110c97b7b93c3e250d93d6e85d69
        136d868807b2dbef568eb680ab52a12d
    ");
    let ofb_ct = hex!("
        db37e0e266903c830d46644c1f9a089c
        a0f83062430e327ec824efb8bd4fdb05
    ");
    let cbc_ct = hex!("
        96d1b05eea683919aff76129abb937b9
        5058b4a1c4bc001920b78b1a7cd7e667
    ");
    let cfb_ct = hex!("
        db37e0e266903c830d46644c1f9a089c
        24bdd2035315d38bbcc0321421075505
    ");

    let c = GostOfb::<Magma, U2>::new(&key, &iv);
    test_stream_cipher(c, &pt, &ofb_ct);

    let c = GostCfb::<Magma, U16>::new(&key, &iv);
    test_stream_cipher(c, &pt, &cfb_ct);

    let c = GostCtr64::<Magma>::new(&key, &ctr_iv);
    test_stream_cipher(c, &pt, &ctr_ct);

    type EcbCipher = Ecb<Magma, ZeroPadding>;
    let cipher = Magma::new(&key);
    let buf = EcbCipher::new(cipher, &Default::default()).encrypt_vec(&pt);
    assert_eq!(buf, &ecb_ct[..]);
    let buf = EcbCipher::new(cipher, &Default::default())
        .decrypt_vec(&ecb_ct)
        .unwrap();
    assert_eq!(buf, &pt[..]);

    type CbcCipher = GostCbc<Magma, ZeroPadding, U3>;
    let cipher = Magma::new(&key);
    let buf = CbcCipher::new(cipher, &cbc_iv).encrypt_vec(&pt);
    assert_eq!(buf, &cbc_ct[..]);
    let buf = CbcCipher::new(cipher, &cbc_iv).decrypt_vec(&cbc_ct).unwrap();
    assert_eq!(buf, &pt[..]);
}

new_seek_test!(kuznyechik_ctr_seek, GostCtr128::<Kuznyechik, U14>);
new_seek_test!(magma_ctr_seek, GostCtr64::<Magma, U5>);
