use crate::snark::{transcript::TranscriptChip, types::proof::ProofValues};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, *},
    dev::MockProver,
    plonk::*,
};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions};
use poseidon::Spec;
use std::marker::PhantomData;

use super::types::{
    assigned::{
        self, AssignedFriProofValues, AssignedHashValues, AssignedOpeningSetValues,
        AssignedProofChallenges, AssignedProofValues, AssignedProofWithPisValues,
        AssignedVerificationKeyValues,
    },
    verification_key::VerificationKeyValues,
};

#[derive(Clone)]
pub struct VerifierConfig<F: FieldExt> {
    main_gate_config: MainGateConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> VerifierConfig<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        VerifierConfig {
            main_gate_config,
            _marker: PhantomData,
        }
    }
}

pub struct Verifier {
    proof: ProofValues<Goldilocks, 2>,
    public_inputs: Vec<Goldilocks>,
    public_inputs_num: usize,
    vk: VerificationKeyValues<Goldilocks>,
    spec: Spec<Goldilocks, 12, 11>,
}

pub fn run_verifier_circuit(
    proof: ProofValues<Goldilocks, 2>,
    public_inputs: Value<Vec<Goldilocks>>,
    public_inputs_num: usize,
    vk: VerificationKeyValues<Goldilocks>,
    spec: Spec<Goldilocks, 12, 11>,
) {
    let verifier_circuit = Verifier {
        proof,
        public_inputs,
        public_inputs_num,
        vk,
        spec,
    };
    let instance = vec![vec![]];
    let _prover = MockProver::run(12, &verifier_circuit, instance).unwrap();
    _prover.assert_satisfied()
}

impl Circuit<Goldilocks> for Verifier {
    type Config = VerifierConfig<Goldilocks>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            proof: ProofValues::default(),
            public_inputs: vec![],
            public_inputs_num: 0,
            vk: VerificationKeyValues::default(),
            spec: Spec::new(8, 22),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Goldilocks>) -> Self::Config {
        VerifierConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Goldilocks>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<Goldilocks>::new(config.main_gate_config.clone());

        layouter.assign_region(
            || "Plonky2 verifier",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                Ok(())
            },
        )?;

        Ok(())
    }
}
