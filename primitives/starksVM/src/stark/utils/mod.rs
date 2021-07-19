use rand::prelude::*;
use rand::distributions::Uniform;
use rand::{Rng};
// use rand_chacha::rand_core::SeedableRng;
// use rand_chacha::rand_core;
// use crate::stark::trace::trace_state::fmt::string::lossy::char::methods::unicode::N;

use super::{ ProofOptions, MAX_CONSTRAINT_DEGREE };
use sp_std::vec::Vec;
// use wasm_bindgen_test::console_log;

// RE-EXPORTS
// ================================================================================================
mod coefficients;
pub use coefficients::{ ConstraintCoefficients, CompositionCoefficients };

mod proof_of_work;
pub use proof_of_work::{ find_pow_nonce, verify_pow_nonce };

pub fn get_composition_degree(trace_length: usize) -> usize {
    return (MAX_CONSTRAINT_DEGREE - 1) * trace_length - 1;
}

// PUBLIC FUNCTIONS
// ================================================================================================

pub fn get_incremental_trace_degree(trace_length: usize) -> usize {
    let composition_degree = get_composition_degree(trace_length);
    return composition_degree - (trace_length - 2);
}

pub fn compute_query_positions(seed: &[u8; 32], domain_size: usize, options: &ProofOptions) -> Vec<usize> {
    let domain_size2 = domain_size as i32;
    let range = Uniform::from(0..domain_size2);

    let mut index_iter = StdRng::from_seed(*seed).sample_iter(range);
    let num_queries = options.num_queries();

    let mut result = Vec::new();

    for _ in 0..1000 {
        let value = index_iter.next().unwrap() as usize;

        if value % options.extension_factor() == 0 { continue; }

        if result.contains(&value) { continue; }
        result.push(value);
        if result.len() >= num_queries { break; }
    }
    if result.len() < num_queries {
        panic!("needed to generate {} query positions, but generated only {}", num_queries, result.len());
    }

    return result;
}

pub fn map_trace_to_constraint_positions(positions: &[usize]) -> Vec<usize> {
    let mut result = Vec::with_capacity(positions.len());
    for &position in positions.iter() {
        let cp = position / 2;
        if !result.contains(&cp) { result.push(cp); }
    }
    return result;
}