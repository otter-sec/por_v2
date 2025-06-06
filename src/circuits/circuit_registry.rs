use std::collections::HashMap;

use plonky2::{hash::hash_types::HashOut, plonk::proof::ProofWithPublicInputs};

use crate::circuits::{batch_circuit::BatchCircuit, recursive_circuit::RecursiveCircuit};
use crate::config::*;

pub struct RecursiveCircuitEntry{
    pub circuit: RecursiveCircuit,
    pub empty_proof: Option<ProofWithPublicInputs<F, C, D>>,
    depth: usize
}

pub struct BatchCircuitEntry{
    pub circuit: BatchCircuit,
    pub empty_proof: ProofWithPublicInputs<F, C, D>,
}

pub struct CircuitRegistry{
    batch_circuit: BatchCircuitEntry,
    recursive_circuits: HashMap<HashOut<F>, RecursiveCircuitEntry>
}


impl CircuitRegistry {
    pub fn new(batch_circuit: BatchCircuit, asset_prices: &[u64]) -> Self {

        let empty_batch_proof = batch_circuit.prove_empty(asset_prices);

        CircuitRegistry {
            batch_circuit: BatchCircuitEntry {
                circuit: batch_circuit,
                empty_proof: empty_batch_proof,
            },
            recursive_circuits: HashMap::new(),
        }
    }

    pub fn get_batch_circuit(&self) -> &BatchCircuit {
        &self.batch_circuit.circuit
    }

    pub fn get_recursive_circuit(&self, digest: HashOut<F>) -> Option<&RecursiveCircuitEntry> {
        self.recursive_circuits.get(&digest)
    }

    pub fn get_empty_proof(&self, circuit_digest: HashOut<F>) -> Option<&ProofWithPublicInputs<F, C, D>> {
        let recursive_entry = self.recursive_circuits.get(&circuit_digest);
        
        if let Some(entry) = recursive_entry {
            // check if the empty proof is already in the registry
            if entry.empty_proof.is_some() {
                return entry.empty_proof.as_ref();
            }
        }

        // if recursive entry is not found it is from the batch circuit (double check)
        if circuit_digest == self.batch_circuit.circuit.circuit_data.verifier_only.circuit_digest {
            return Some(&self.batch_circuit.empty_proof);
        }

        None
    }

    pub fn add_recursive_circuit(&mut self, circuit: RecursiveCircuit, depth: usize) {

        let digest = circuit.circuit_data.verifier_only.circuit_digest;

        if depth == 1 { // dont need to prove empty for root
            self.recursive_circuits.insert(digest, RecursiveCircuitEntry { circuit, empty_proof: None, depth });
            return;
        }

        let empty_proof = circuit.prove_empty(self);
        self.recursive_circuits.insert(digest, RecursiveCircuitEntry { circuit, empty_proof: Some(empty_proof), depth });
    }

    pub fn get_recursive_circuit_by_depth(&self, depth: usize) -> Option<&RecursiveCircuitEntry> {
        self.recursive_circuits.values().find(|&entry| entry.depth == depth)
    }
}