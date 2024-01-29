use crate::snark::types::{HashValues, MerkleCapValues};
use halo2_proofs::halo2curves::ff::PrimeField;
use plonky2::plonk::{circuit_data::VerifierOnlyCircuitData, config::PoseidonGoldilocksConfig};

#[derive(Clone, Debug, Default)]
pub struct VerificationKeyValues<F: PrimeField> {
    pub constants_sigmas_cap: MerkleCapValues<F>,
    pub circuit_digest: HashValues<F>,
}

impl<F: PrimeField> From<VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>>
    for VerificationKeyValues<F>
{
    fn from(value: VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>) -> Self {
        VerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::from(value.constants_sigmas_cap),
            circuit_digest: HashValues::from(value.circuit_digest),
        }
    }
}
