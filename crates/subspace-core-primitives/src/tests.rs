use crate::{Scalar, PIECE_SIZE, PLOT_SECTOR_SIZE, U256};
//use ark_ff::ToConstraintField;
use num_integer::Roots;
use rand::thread_rng;
use rand_core::RngCore;

#[test]
fn piece_distance_middle() {
    assert_eq!(U256::MIDDLE, U256::MAX / 2);
}

#[test]
fn piece_size_multiple_of_and_scalar() {
    assert_eq!(PIECE_SIZE % Scalar::SAFE_BYTES, 0);
}

#[test]
fn sector_side_size_in_scalars_power_of_two() {
    let sector_size_in_scalars = PLOT_SECTOR_SIZE / Scalar::SAFE_BYTES as u64;
    let sector_side_size_in_scalars = sector_size_in_scalars.sqrt();

    assert!(sector_side_size_in_scalars.is_power_of_two());
}

#[test]
fn bytes_scalars_conversion() {
    {
        let mut bytes = vec![0u8; Scalar::SAFE_BYTES * 16];
        thread_rng().fill_bytes(&mut bytes);

        let scalars = bytes
            .chunks_exact(Scalar::SAFE_BYTES)
            .map(Scalar::try_from)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(Scalar::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    scalar.write_to_bytes(bytes).unwrap();
                });

            assert_eq!(bytes, decoded_bytes);
        }

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(Scalar::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    bytes.copy_from_slice(&scalar.to_bytes());
                });

            assert_eq!(bytes, decoded_bytes);
        }
    }

    {
        let bytes = rand::random::<[u8; Scalar::SAFE_BYTES]>();

        {
            let scalar = Scalar::try_from(&bytes).unwrap();

            assert_eq!(bytes, scalar.to_bytes());
        }

        {
            let scalar = Scalar::from(&bytes);

            assert_eq!(bytes, scalar.to_bytes());
        }
    }
}
#[test]
fn test_fft_bytes() {
    use ark_bls12_381::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain,UVPolynomial,Polynomial};
    use ark_poly::univariate::DensePolynomial;
    use rand::random;

    //this gotta be 32, fails with 31
    const SAFE_BYTES: usize = 32;

    fn to_scalar(value: &[u8; SAFE_BYTES]) -> Fr {
        //this is guaranteed to fit in field
        Fr::from_le_bytes_mod_order(value)
    }

    fn to_bytes(value: &Fr) -> [u8; SAFE_BYTES] {
        let mut bytes = [0u8; SAFE_BYTES];

        let vec = value.into_repr().to_bytes_le();
        for i in 0..SAFE_BYTES{
            bytes[i]=vec[i];
        }
        bytes
    }
    
    let bytes = vec![
        random::<[u8; SAFE_BYTES]>(),
        random::<[u8; SAFE_BYTES]>(),
        random::<[u8; SAFE_BYTES]>(),
        random::<[u8; SAFE_BYTES]>(),
    ];
    let mut scalars = bytes.iter().map(to_scalar).collect::<Vec<Fr>>();


    let safe_bytes = scalars
        .iter()
        .map(to_bytes)
        .collect::<Vec<[u8; SAFE_BYTES]>>();

    //these are equal with high probability, but may be not equal as bytes were taken modulo field order
    //if we want them always equal we should explicitly have 0 as last byte in all bytes[]
    //assert_eq!(bytes, safe_bytes);

    let domain = GeneralEvaluationDomain::<Fr>::new(bytes.len()).unwrap();

    //this will be codec.encode
    domain.ifft_in_place(&mut scalars);
    domain.coset_fft_in_place(&mut scalars);

    //convert to bytes
    let coded_bytes = scalars
        .iter()
        .map(to_bytes)
        .collect::<Vec<[u8; SAFE_BYTES]>>();

    // Values are not the same as original when transformation is applied
    assert_ne!(safe_bytes, coded_bytes);
    
    //convert back to bytes
    let mut coded_scalars = coded_bytes.iter().map(to_scalar).collect::<Vec<Fr>>();

    assert_eq!(coded_scalars, scalars);

    //this will be codec.decode
    let mut decoded_scalars = Vec::with_capacity(bytes.len());
    domain.coset_ifft_in_place(&mut coded_scalars);
    let poly_from_coded =
                DensePolynomial::from_coefficients_vec(coded_scalars);

    for x in domain.elements() {

        decoded_scalars.push(poly_from_coded.evaluate(&x));
    }

    //convert to bytes
    let decoded_bytes = decoded_scalars
        .iter()
        .map(to_bytes)
        .collect::<Vec<[u8; SAFE_BYTES]>>();

    //should be same as original after modulo
    assert_eq!(decoded_bytes, safe_bytes)

}