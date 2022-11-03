use crate::crypto::kzg::dusk_bytes::Serializable;
use crate::crypto::kzg::{BlsScalar, Kzg, Kzg2};
use ark_bls12_381::Fr;
use ark_ff::fields::PrimeField;
use ark_ff::FpParameters;

#[test]
fn basic() {
    let data = {
        // Multiple of 32
        let mut data = rand::random::<[u8; 256]>();

        // We can only store 254 bits, set last byte to zero because of that
        data.chunks_exact_mut(BlsScalar::SIZE)
            .flat_map(|chunk| chunk.iter_mut().last())
            .for_each(|last_byte| *last_byte = 0);

        data
    };

    let kzg = Kzg::random(256).unwrap();
    let polynomial = kzg.poly(&data).unwrap();
    let commitment = kzg.commit(&polynomial).unwrap();

    let values = data.chunks_exact(BlsScalar::SIZE);

    for (index, value) in values.enumerate() {
        let index = index.try_into().unwrap();

        let witness = kzg.create_witness(&polynomial, index).unwrap();

        assert!(
            kzg.verify(&commitment, index, value, &witness),
            "failed on index {index}"
        );
    }
}

#[test]
fn basic2() {
    let data = {
        // Multiple of 32
        let mut data = rand::random::<[u8; 256]>();

        // We can only store 254 bits, set last byte to zero because of that
        data.chunks_exact_mut(BlsScalar::SIZE)
            .flat_map(|chunk| chunk.iter_mut().last())
            .for_each(|last_byte| *last_byte = 0);

        data
    };

    let kzg = Kzg2::random(256).unwrap();
    let values = data
        .chunks_exact(<Fr as PrimeField>::Params::CAPACITY.div_ceil(u8::BITS) as usize)
        .map(Fr::from_le_bytes_mod_order)
        .collect::<Vec<_>>();
    let polynomial = kzg.poly(values.clone());
    let commitment = kzg.commit(&polynomial).unwrap();

    for (index, value) in values.into_iter().enumerate() {
        let index = index.try_into().unwrap();

        let witness = kzg.create_witness(&polynomial, index).unwrap();

        assert!(
            kzg.verify(commitment, index, value, witness),
            "failed on index {index}"
        );
    }
}
