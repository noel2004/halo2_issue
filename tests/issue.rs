

use halo2_proofs_pse as halo2_proofs;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, Circuit},
    poly::Rotation,
};

use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[derive(Clone, Debug)]
struct IssueCircuitConfig {
    sel: Selector,
    col: Column<Advice>,
}

#[derive(Clone, Default)]
struct IssueCircuit;

impl Circuit<Fp> for IssueCircuit {
    type Config = IssueCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

        let sel = meta.selector();
        let col = meta.advice_column();

        meta.create_gate("issue gate", |meta|{
            let sel = meta.query_selector(sel);
            let col = meta.query_advice(col, Rotation::cur());

            // Following gate would be ok
            // vec![sel * (col - Expression::Constant(Fp::zero()))]
            
            vec![sel * (Expression::Constant(Fp::zero()) - col)]
        });

        Self::Config {sel, col}
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                config.sel.enable(&mut region, 0)?;
                region.assign_advice(||"cell", config.col, 0, ||Ok(Fp::zero()))?;
                Ok(())
            }
        )
    }
}


#[test]
fn proof_and_verify() {

    let k = 5;

    let params = Params::<G1Affine>::unsafe_setup::<Bn256>(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let circuit = IssueCircuit{};

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    create_proof(&params, &pk, &[circuit.clone()], &[&[]], os_rng, &mut transcript).unwrap();

    let proof_script = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier(0).unwrap();
    let strategy = SingleVerifier::new(&verifier_params);
    let vk = keygen_vk(&params, &circuit).unwrap();

    verify_proof(&verifier_params, &vk, strategy, &[&[]], &mut transcript).unwrap();
}
