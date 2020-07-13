//! Test vectors from:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/idea/Idea-128-64.verified.test-vectors

block_cipher::new_test!(idea_test, "idea", idea::Idea);
