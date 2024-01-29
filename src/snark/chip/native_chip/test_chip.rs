use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use halo2wrong::RegionCtx;

// a*b + c = q*p + r, with range check of q and r
#[derive(Clone, Debug)]
pub struct TestChipConfig<F: PrimeField> {
    pub a: Column<Advice>,
    pub b: Column<Fixed>,
    pub selector: Selector,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> TestChipConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.fixed_column();
        let selector = meta.selector();

        meta.create_gate("main constraint", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_fixed(b, Rotation::cur());
            let s = meta.query_selector(selector);
            vec![s * (a - b)]
        });

        TestChipConfig {
            a,
            b,
            selector,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TestChip<F: PrimeField> {
    config: TestChipConfig<F>,
}

impl<F: PrimeField> TestChip<F> {
    pub fn new(config: &TestChipConfig<F>) -> Self {
        TestChip {
            config: config.clone(),
        }
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        ctx.constrain_equal(a.cell(), b.cell())?;
        Ok(())
    }

    pub fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: Value<F>,
        b: F,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        ctx.enable(self.config.selector)?;
        let a = ctx.assign_advice(|| "a", self.config.a, a)?;
        let b = ctx.assign_fixed(|| "b", self.config.b, b)?;
        ctx.next();
        Ok((a, b))
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2wrong::RegionCtx;

    use super::TestChipConfig;

    #[derive(Clone, Default)]
    pub struct TestCircuit;

    impl Circuit<Fr> for TestCircuit {
        type Config = TestChipConfig<Fr>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            TestChipConfig::<Fr>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = super::TestChip::new(&config);

            layouter.assign_region(
                || "Verify proof",
                |region| {
                    let ctx = &mut RegionCtx::new(region, 0);
                    let (a, b) = chip.assign(ctx, Value::known(1.into()), 1.into())?;
                    chip.assign(ctx, b.value().cloned(), 1.into())?;

                    dbg!(a.value());
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_test_chip_mock() {
        let circuit = TestCircuit;
        let instance = vec![];
        let mock_prover = MockProver::run(17, &circuit, vec![instance.clone()]).unwrap();
        mock_prover.assert_satisfied();
    }
}
