//! Test vectors from:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/idea/Idea-128-64.verified.test-vectors

cipher::block_cipher_test!(idea_test, "idea", idea::Idea);
