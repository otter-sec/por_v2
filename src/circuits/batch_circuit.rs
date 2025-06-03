use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::serialization::gate_serialization::log::Level;
use plonky2::util::timing::TimingTree;
use crate::config::*;

// builder configs
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type H = <C as GenericConfig<D>>::Hasher;

#[derive(Clone, Debug)]
pub struct Account {
    asset_balances: Vec<Target>,
    equity: Target,
}

#[derive(Debug)]
pub struct BatchCircuit {
    asset_prices_target: Vec<Target>,
    account_targets: Vec<Account>,
    leaf_hashes: Vec<HashOutTarget>,
    pub circuit_data: CircuitData<F, C, D>,
}

impl BatchCircuit {
    pub fn new(asset_count: usize) -> BatchCircuit {
        let config = BATCH_CIRCUIT_CONFIG;
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // create a circuit that takes BATCH_SIZE inputs and check these constraints
        // --> Calculate account equity (sum of "asset * price")
        // --> Constraint account equity non-negativity
        // --> Calculate sum of all assets of all accounts

        let mut accounts: Vec<Account> = Vec::new();

        let asset_prices_target = builder.add_virtual_targets(asset_count);

        // create targets for each leaf
        for _ in 0..BATCH_SIZE {
            let asset_balances = builder.add_virtual_targets(asset_count);

            let account = Account {
                asset_balances,
                equity: builder.zero(),
            };
            accounts.push(account);
        }

        // create the non-negativy constraint
        for account in &mut accounts {
            account.equity = account
                .asset_balances
                .iter()
                .zip(asset_prices_target.iter())
                .fold(account.equity, |acc, (balance, value)| {
                    builder.mul_add(*balance, *value, acc)
                });

            builder.range_check(account.equity, 62);
        }

        // calculate the sum of all assets of all accounts
        let total_asset_values = builder.add_virtual_targets(asset_count);

        for i in 0..asset_count {
            let mut sum = builder.zero();
            for account in &accounts {
                let new_sum = builder.add(account.asset_balances[i], sum);

                // CONSTRAINT: check if not overflowing
                // since asset balances can be negative, we need to ensure the difference
                // of new_sum and sum is equal to the account.asset_balances[i]. If it is not,
                // it means that the sum has overflowed.
                let diff = builder.sub(new_sum, sum);
                let not_overflowed = builder.is_equal(diff, account.asset_balances[i]);
                builder.assert_bool(not_overflowed);

                // update sum
                sum = new_sum;
            }
            builder.connect(sum, total_asset_values[i]);
        }

        // leaf hashes to calculate root hash
        let leaf_hashes = builder.add_virtual_hashes(BATCH_SIZE as usize);

        // calculate root hash by concatenating all leaf hashes
        let concat_hashes = leaf_hashes.iter().fold(Vec::new(), |mut acc, hash| {
            acc.push(hash.elements[0]);
            acc.push(hash.elements[1]);
            acc.push(hash.elements[2]);
            acc.push(hash.elements[3]);
            acc
        });

        let root_hash = builder.hash_n_to_hash_no_pad::<H>(concat_hashes);

        // register the public inputs
        builder.register_public_inputs(&total_asset_values); // sum of all assets of BATCH_SIZE accounts
        builder.register_public_inputs(&asset_prices_target);
        builder.register_public_inputs(&root_hash.elements);

        let circuit = builder.build::<C>();

        BatchCircuit {
            asset_prices_target,
            leaf_hashes: leaf_hashes,
            account_targets: accounts,
            circuit_data: circuit,
        }
    }

    pub fn prove_batch_circuit(
        &self,
        asset_prices: &Vec<u64>,
        accounts: &[Vec<i64>],
        leaf_hashes: &Vec<HashOut<F>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();

        // check if accounts length is equal to BATCH_SIZE
        assert!(
            accounts.len() == BATCH_SIZE as usize,
            "The number of accounts must be equal to BATCH_SIZE"
        );

        // convert the asset prices to GoldilocksField
        let asset_prices: Vec<F> = asset_prices
            .iter()
            .map(|&price| {
                let price = price as u64;
                F::from_canonical_u64(price)
            })
            .collect();

        // convert the account balances to GoldilocksField
        let account_balances: Vec<Vec<F>> = accounts
            .iter()
            .map(|account| {
                account
                    .iter()
                    .map(|&balance| {
                        let balance = balance;
                        F::from_noncanonical_i64(balance)
                    })
                    .collect()
            })
            .collect();

        // set the asset prices
        pw.set_target_arr(&self.asset_prices_target, asset_prices.as_slice())?;

        // set account targets
        for (i, account) in self.account_targets.iter().enumerate() {
            pw.set_target_arr(&account.asset_balances, account_balances[i].as_slice())?;
        }

        // set leaf hashes
        for (i, leaf_hash) in self.leaf_hashes.iter().enumerate() {
            pw.set_hash_target(*leaf_hash, leaf_hashes[i])?;
        }

        let mut timing = TimingTree::new("prove", Level::Trace);
        let proof = prove::<F, C, D>(
            &self.circuit_data.prover_only,
            &self.circuit_data.common,
            pw,
            &mut timing,
        )?;

        timing.print();

        Ok(proof)
    }

    pub fn prove_empty(&self, asset_prices: &Vec<u64>) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::<F>::new();

        let assset_count = self.asset_prices_target.len();

        // convert asset_prices to Field vector and set the asset prices
        let asset_prices: Vec<F> = asset_prices
            .iter()
            .map(|&price| {
                let price = price as u64;
                F::from_canonical_u64(price)
            })
            .collect();
        pw.set_target_arr(&self.asset_prices_target, &asset_prices).unwrap();

        // set account targets
        for (_, account) in self.account_targets.iter().enumerate() {
            pw.set_target_arr(&account.asset_balances, vec![F::from_noncanonical_i64(0); assset_count].as_slice()).unwrap();
        }

        // set leaf hashes
        for (_, leaf_hash) in self.leaf_hashes.iter().enumerate() {
            pw.set_hash_target(*leaf_hash, HashOut::<F>::default()).unwrap();
        }

        let mut timing = TimingTree::new("prove empty batch", Level::Trace);
        let proof = prove::<F, C, D>(
            &self.circuit_data.prover_only,
            &self.circuit_data.common,
            pw,
            &mut timing,
        ).unwrap();

        timing.print();

        proof
    }

    // Verify a proof
    pub fn verify_batch_circuit(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<()> {
    
        let res = self.circuit_data.verify(proof);

        if res.is_err() {
            panic!("Verification failed");
        }

        Ok(())
    }
    
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
        let end = asset_count*2;
        start..end
    }

    // root hash public input
    pub fn get_root_hash_offset(asset_count: usize) -> std::ops::Range<usize> {
        let start = asset_count*2;
        let end = start + 4;
        start..end
    }
}
