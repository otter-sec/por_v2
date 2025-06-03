use plonky2::plonk::circuit_builder::CircuitBuilder;    
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::field::types::Field;
use crate::config::*;   

#[inline]
pub fn is_negative(builder: &mut CircuitBuilder<F, D>, x: Target) -> BoolTarget {
    let min_neg = F::from_canonical_u64(9223372034707292161u64);

    let min_neg_target = builder.constant(min_neg);
    let divided = builder.div(x, min_neg_target);
    let one = builder.one();
    let is_negative = builder.is_equal(divided, one);

    return is_negative;
}

pub fn is_positive(builder: &mut CircuitBuilder<F, D>, x: Target) -> BoolTarget {
    let is_negative = is_negative(builder, x);
    return builder.not(is_negative);
}