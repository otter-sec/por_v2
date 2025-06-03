use crate::circuits::circuit_registry::*;
use crate::config::*;
use crate::utils::circuit_helper::*;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::plonk::prover::prove;
use plonky2::util::serialization::gate_serialization::log::Level;
use plonky2::util::timing::TimingTree;

// builder configs
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type H = <C as GenericConfig<D>>::Hasher;

#[derive(Debug)]
pub struct RecursiveCircuit {
    pub circuit_data: CircuitData<F, C, D>,
    inner_circuit_data_verifier: VerifierOnlyCircuitData<C, D>,
    inner_circuit_targets: Vec<InnerCircuitTargets>,
    // children_hashes_targets: Vec<HashOutTarget>,
}

#[derive(Debug)]
struct InnerCircuitTargets {
    proof_target: ProofWithPublicInputsTarget<D>,
    verifier_target: VerifierCircuitTarget,
    asset_balances: Vec<Target>,
}

impl RecursiveCircuit {
    pub fn new(inner_circuit: &CircuitData<F, C, D>, asset_count: usize) -> RecursiveCircuit {
        let config = RECURSIVE_CIRCUIT_CONFIG;
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // create a circuit that takes RECURSIVE_SIZE (n) inputs (inner_circuit proofs) and check these constraints
        // --> Verify n proofs
        // --> Calculate sum of all inner_circuit balances (maybe store in 2 64bit targets)
        // --> Check if no overflow

        // create targets for batch proofs (input)
        let mut inner_targets = Vec::new();
        for _ in 0..RECURSIVE_SIZE {
            let proof_target = builder.add_virtual_proof_with_pis(&inner_circuit.common);
            let verify_target = builder
                .add_virtual_verifier_data(inner_circuit.common.config.fri_config.cap_height);

            // create targets for summed balances of batch circuit (input)
            // let batch_balance = builder.add_virtual_targets(asset_count);
            let balances_offset = RecursiveCircuit::get_final_balances_offset(asset_count);
            let batch_balance = proof_target.public_inputs[balances_offset].to_vec();

            let inner_data = InnerCircuitTargets {
                proof_target,
                verifier_target: verify_target,
                asset_balances: batch_balance,
            };

            // CONSTRAINT: add verify proof constraint
            builder.verify_proof::<C>(
                &inner_data.proof_target,
                &inner_data.verifier_target,
                &inner_circuit.common,
            );

            inner_targets.push(inner_data);
        }

        let mut final_balances = Vec::new();

        // iterate through assets to sum all balances
        for i in 0..asset_count {
            final_balances.push(builder.zero());
            for inner_data in &inner_targets {
                // sum all balances of the inner circuits
                let new_summed_bal = builder.add(inner_data.asset_balances[i], final_balances[i]);

                // CONSTRAINT: check if not overflowing
                // the only way to overflow is if two positive numbers are added together and the result is negative
                // since we allow overflows with negative numbers (negative numbers intentionally uses overflows)
                let is_sum1_positive = is_positive(&mut builder, inner_data.asset_balances[i]);
                let is_sum2_positive = is_positive(&mut builder, final_balances[i]);
                let is_both_positive = builder.and(is_sum1_positive, is_sum2_positive);
                let is_result_negative = is_negative(&mut builder, new_summed_bal);

                let is_overflow = builder.and(is_both_positive, is_result_negative);
                let is_not_overflow = builder.not(is_overflow);
                builder.assert_bool(is_not_overflow);

                final_balances[i] = new_summed_bal;
            }
        }

        // get the asset prices
        let asset_prices = inner_targets[0].proof_target.public_inputs
            [RecursiveCircuit::get_asset_prices_offset(asset_count)]
        .to_vec();

        // iterate through all circuits to verify if the asset prices are the same
        for inner_target in inner_targets.iter().take(RECURSIVE_SIZE) {
            let inner_asset_prices = inner_target.proof_target.public_inputs
                [RecursiveCircuit::get_asset_prices_offset(asset_count)]
            .to_vec();

            // CONSTRAINT: check if asset prices are the same
            // we cannot use builder.connect_array() since we are using Vec
            for j in 0..asset_count {
                builder.connect(inner_asset_prices[j], asset_prices[j]);
            }
        }

        // iterate through proofs to create the hashes
        let mut concat_hashes = Vec::new();
        for inner_target in inner_targets.iter().take(RECURSIVE_SIZE) {
            let hash_elements = inner_target.proof_target.public_inputs
                [RecursiveCircuit::get_root_hash_offset(asset_count)]
            .to_vec();

            concat_hashes.extend(hash_elements);
        }

        let root_hash = builder.hash_n_to_hash_no_pad::<H>(concat_hashes);

        // register public inputs
        builder.register_public_inputs(&final_balances); // sum of all assets of BATCH_SIZE accounts
        builder.register_public_inputs(&asset_prices); // asset prices in USD (each one with different decimals)
        builder.register_public_inputs(&root_hash.elements); // root hash of the inner circuits

        RecursiveCircuit {
            inner_circuit_data_verifier: inner_circuit.verifier_only.clone(),
            circuit_data: builder.build::<C>(),
            inner_circuit_targets: inner_targets,
        }
    }

    pub fn prove_recursive_circuit(
        &self,
        subproofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::new();

        // set the inner circuit proofs
        for (i, inner_data) in self.inner_circuit_targets.iter().enumerate() {
            pw.set_proof_with_pis_target(&inner_data.proof_target, &subproofs[i])
                .unwrap();
            pw.set_verifier_data_target(
                &inner_data.verifier_target,
                &self.inner_circuit_data_verifier,
            )
            .unwrap();
        }

        // prove the circuit
        let mut timing = TimingTree::new("prove recursive", Level::Trace);
        let proof = prove::<F, C, D>(
            &self.circuit_data.prover_only,
            &self.circuit_data.common,
            pw,
            &mut timing,
        )
        .unwrap();

        timing.print();

        // return the proof
        proof
    }

    pub fn prove_empty(
        &self,
        circuit_registry: &mut CircuitRegistry,
    ) -> ProofWithPublicInputs<F, C, D> {
        let current_digest = self.circuit_data.verifier_only.circuit_digest;

        // see if it is already in the registry and return
        let cached_proof = circuit_registry.get_empty_proof(current_digest);
        if let Some(proof) = cached_proof {
            return proof.clone();
        }

        // else, create the empty proof
        let inner_digest = self.inner_circuit_data_verifier.circuit_digest;

        // get the inner circuit empty proof
        let inner_empty_proof = circuit_registry.get_empty_proof(inner_digest).unwrap();

        // create and return a new proof with the empty proof as input
        self.prove_recursive_circuit(vec![inner_empty_proof.clone(); RECURSIVE_SIZE])
    }

    // CAUTION: all offsets must be the same as in the batch circuit

    // final balances public input
    pub fn get_final_balances_offset(asset_count: usize) -> std::ops::Range<usize> {
        let start = 0;
        let end = asset_count;
        start..end
    }

    // asset prices
    pub fn get_asset_prices_offset(asset_count: usize) -> std::ops::Range<usize> {
        // after the root hash
        let start = asset_count;
        let end = asset_count * 2;
        start..end
    }

    // root hash public input
    pub fn get_root_hash_offset(asset_count: usize) -> std::ops::Range<usize> {
        let start = asset_count * 2;
        let end = start + 4;
        start..end
    }
}
