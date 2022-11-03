#![feature(int_roundings)]

use ark_bls12_381::Fr;
use ark_ff::{FpParameters, PrimeField};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use subspace_core_primitives::crypto::kzg::{Kzg, Kzg2};

fn criterion_benchmark(c: &mut Criterion) {
    let data = {
        // Multiple of 32
        let mut data = rand::random::<[u8; 256]>();

        // We can only store 254 bits, set last byte to zero because of that
        data.chunks_exact_mut(BlsScalar::SIZE)
            .flat_map(|chunk| chunk.iter_mut().last())
            .for_each(|last_byte| *last_byte = 0);

        data
    };

    {
        let kzg = Kzg::random(256).unwrap();

        c.bench_function("create-polynomial", |b| {
            b.iter(|| {
                kzg.poly(black_box(&data)).unwrap();
            })
        });

        c.bench_function("commit", |b| {
            let polynomial = kzg.poly(&data).unwrap();
            b.iter(|| {
                kzg.commit(black_box(&polynomial)).unwrap();
            })
        });

        c.bench_function("create-witness", |b| {
            let polynomial = kzg.poly(&data).unwrap();

            b.iter(|| {
                kzg.create_witness(black_box(&polynomial), black_box(0))
                    .unwrap();
            })
        });

        c.bench_function("verify", |b| {
            let polynomial = kzg.poly(&data).unwrap();
            let commitment = kzg.commit(&polynomial).unwrap();
            let index = 0;
            let witness = kzg.create_witness(&polynomial, index).unwrap();
            let value = &data[..BlsScalar::SIZE];

            b.iter(|| {
                kzg.verify(
                    black_box(&commitment),
                    black_box(index),
                    black_box(value),
                    black_box(&witness),
                );
            })
        });
    }

    {
        let kzg2 = Kzg2::random(256).unwrap();
        let values = data
            .chunks_exact(<Fr as PrimeField>::Params::CAPACITY.div_ceil(u8::BITS) as usize)
            .map(Fr::from_le_bytes_mod_order)
            .collect::<Vec<_>>();

        c.bench_function("create-polynomial-2", |b| {
            b.iter(|| {
                kzg2.poly(black_box(values.clone()));
            })
        });

        c.bench_function("commit-2", |b| {
            let polynomial = kzg2.poly(values.clone());
            b.iter(|| {
                let _ = kzg2.commit(black_box(&polynomial)).unwrap();
            })
        });

        c.bench_function("create-witness-2", |b| {
            let polynomial = kzg2.poly(values.clone());

            b.iter(|| {
                let _ = kzg2
                    .create_witness(black_box(&polynomial), black_box(0))
                    .unwrap();
            })
        });

        c.bench_function("verify-2", |b| {
            let polynomial = kzg2.poly(values.clone());
            let commitment = kzg2.commit(&polynomial).unwrap();
            let index = 0;
            let witness = kzg2.create_witness(&polynomial, index).unwrap();
            let value = values[0];

            b.iter(|| {
                kzg2.verify(
                    black_box(commitment),
                    black_box(index),
                    black_box(value),
                    black_box(witness),
                );
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
