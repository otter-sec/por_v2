use plonky2::{fri::{reduction_strategies::FriReductionStrategy, FriConfig}, plonk::{circuit_data::CircuitConfig, config::{GenericConfig, PoseidonGoldilocksConfig}}};

// change size of each circuits here
pub const BATCH_SIZE: usize = 1024;
pub const RECURSIVE_SIZE: usize = 8;

// these should not be changed without refactoring large part of the code
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig; 
pub type F = <C as GenericConfig<D>>::F;
pub type H = <C as GenericConfig<D>>::Hasher;

// batch circuit config
pub const BATCH_CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
    num_wires: 135,
    num_routed_wires: 50,
    num_constants: 2,
    use_base_arithmetic_gate: true,
    security_bits: 100,
    num_challenges: 2,
    zero_knowledge: false, // DOESNT NEED TO BE ZERO KNOWLEDGE SINCE IT WONT BE PUBLIC
    max_quotient_degree_factor: 8,
    fri_config: FriConfig {
        rate_bits: 3,
        cap_height: 4,
        proof_of_work_bits: 16,
        reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
        num_query_rounds: 28,
    }
};

// recursive circuit config
pub const RECURSIVE_CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
    num_wires: 135,
    num_routed_wires: 80,
    num_constants: 2,
    use_base_arithmetic_gate: true,
    security_bits: 100,
    num_challenges: 2,
    zero_knowledge: false, // NEED TO BE ZERO KNOWLEDGE TO PREVENT REVEALING SENSITIVE INFORMATION
    max_quotient_degree_factor: 8,
    fri_config: FriConfig {
        rate_bits: 3,
        cap_height: 4,
        proof_of_work_bits: 16,
        reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
        num_query_rounds: 28,
    }
};
