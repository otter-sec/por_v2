use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::serialization::gate_serialization::log::Level;
use plonky2::util::timing::TimingTree;
use crate::utils::circuit_helper::*;
use crate::config::*;

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

            // builder.range_check(account.equity, 62);
            let is_negative = is_negative(&mut builder, account.equity);
            builder.assert_bool(is_negative);


            // CONSTRAINT: check if not overflowing
            // this is a faster way to check if not overflowing
            // we check if a single balance is not higher than MAX_ACCOUNT_BALANCE
            // MAX_ACCOUNT_BALANCE is calculated based on the number of users in a batch circuit
            // and the max possible integer value (we use 2^62)
            let _ = account.asset_balances.iter().map(|balance| {
                builder.range_check(*balance, MAX_ACCOUNT_BALANCE_BITS);
            });
        }

        
        // calculate the sum of all assets of all accounts
        let total_asset_values = builder.add_virtual_targets(asset_count);

        for (i, total_value) in total_asset_values.iter().enumerate().take(asset_count) {
            let mut sum = builder.zero();
            for account in &accounts {
                sum = builder.add(account.asset_balances[i], sum);
            }
            builder.connect(sum, *total_value);
        }

        // leaf hashes to calculate root hash
        let leaf_hashes = builder.add_virtual_hashes(BATCH_SIZE);

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
            leaf_hashes,
            account_targets: accounts,
            circuit_data: circuit,
        }
    }

    pub fn prove_batch_circuit(
        &self,
        asset_prices: &[u64],
        accounts: &[Vec<i64>],
        leaf_hashes: &[HashOut<F>],
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();

        // check if accounts length is equal to BATCH_SIZE
        assert!(
            accounts.len() == BATCH_SIZE,
            "The number of accounts must be equal to BATCH_SIZE"
        );

        // convert the asset prices to Numeric Field
        let asset_prices: Vec<F> = asset_prices
            .iter()
            .map(|&p| F::from_canonical_u64(p))
            .collect();

        // convert the account balances to Numeric Field
        let account_balances: Vec<Vec<F>> = accounts
            .iter()
            .map(|account| {
                account
                    .iter()
                    .map(|&b| F::from_noncanonical_i64(b))
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

    pub fn prove_empty(&self, asset_prices: &[u64]) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::<F>::new();

        let assset_count = self.asset_prices_target.len();

        // convert asset_prices to Field vector and set the asset prices
        let asset_prices: Vec<F> = asset_prices
            .iter()
            .map(|&p| F::from_canonical_u64(p))
            .collect();
        pw.set_target_arr(&self.asset_prices_target, &asset_prices).unwrap();

        // set account targets
        for account in self.account_targets.iter() {
            pw.set_target_arr(&account.asset_balances, vec![F::from_noncanonical_i64(0); assset_count].as_slice()).unwrap();
        }

        // set leaf hashes
        for leaf_hash in self.leaf_hashes.iter() {
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
