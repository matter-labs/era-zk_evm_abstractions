use crate::aux::*;
use crate::queries::*;
use crate::vm::*;

pub mod ecadd;
pub mod ecmul;
pub mod ecpairing;
pub mod ecrecover;
pub mod keccak256;
pub mod modexp;
pub mod secp256r1_verify;
pub mod sha256;

use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use zkevm_opcode_defs::system_params::ECMUL_INNER_FUNCTION_PRECOMPILE_ADDRESS;
use zkevm_opcode_defs::system_params::ECPAIRING_INNER_FUNCTION_PRECOMPILE_ADDRESS;
use zkevm_opcode_defs::system_params::MODEXP_INNER_FUNCTION_PRECOMPILE_ADDRESS;
use zkevm_opcode_defs::system_params::{
    ECADD_INNER_FUNCTION_PRECOMPILE_ADDRESS, ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS, SECP256R1_VERIFY_PRECOMPILE_ADDRESS,
    SHA256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
};

use zkevm_opcode_defs::PrecompileCallABI;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum PrecompileAddress {
    Ecrecover = ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    SHA256 = SHA256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
    Keccak256 = KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
    EcAdd = ECADD_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    EcMul = ECMUL_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    EcPairing = ECPAIRING_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    Modexp = MODEXP_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    Secp256r1Verify = SECP256R1_VERIFY_PRECOMPILE_ADDRESS,
}

#[derive(Clone, Copy, Debug)]
pub struct PrecompileCallParams {
    pub input_location: MemoryLocation,
    pub timestamp_for_input_read: Timestamp,
    pub output_location: MemoryLocation,
    pub timestamp_for_output_write: Timestamp,
}

pub const fn precompile_abi_in_log(query: LogQuery) -> PrecompileCallABI {
    PrecompileCallABI::from_u256(query.key)
}

#[derive(Clone, Copy, Debug)]
pub struct DefaultPrecompilesProcessor<const B: bool>;

impl<const B: bool> PrecompilesProcessor for DefaultPrecompilesProcessor<B> {
    fn start_frame(&mut self) {
        // there are no precompiles to rollback, do nothing
    }
    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, PrecompileCyclesWitness)> {
        let address_low = u16::from_le_bytes([query.address.0[19], query.address.0[18]]);
        let Ok(precompile_address) = PrecompileAddress::try_from(address_low) else {
            // it's formally allowed for purposes of ergs-burning
            // by special contracts
            return None;
        };

        match precompile_address {
            PrecompileAddress::Keccak256 => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        keccak256::keccak256_rounds_function::<M, B>(
                            monotonic_cycle_counter,
                            query,
                            memory,
                        )
                        .1
                        .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Keccak256(round_witness),
                    ))
                } else {
                    let _ = keccak256::keccak256_rounds_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::SHA256 => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) = sha256::sha256_rounds_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    )
                    .1
                    .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Sha256(round_witness),
                    ))
                } else {
                    let _ = sha256::sha256_rounds_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::Ecrecover => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) = ecrecover::ecrecover_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    )
                    .1
                    .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::ECRecover(round_witness),
                    ))
                } else {
                    let _ = ecrecover::ecrecover_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::Secp256r1Verify => {
                if B {
                    let (reads, writes, round_witness) =
                        secp256r1_verify::secp256r1_verify_function::<M, B>(
                            monotonic_cycle_counter,
                            query,
                            memory,
                        )
                        .1
                        .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Secp256r1Verify(round_witness),
                    ))
                } else {
                    let _ = secp256r1_verify::secp256r1_verify_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::EcAdd => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        ecadd::ecadd_function::<M, B>(monotonic_cycle_counter, query, memory)
                            .1
                            .expect("must generate intermediate witness");

                    Some((reads, writes, PrecompileCyclesWitness::ECAdd(round_witness)))
                } else {
                    let _ = ecadd::ecadd_function::<M, B>(monotonic_cycle_counter, query, memory);

                    None
                }
            }
            PrecompileAddress::EcMul => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        ecmul::ecmul_function::<M, B>(monotonic_cycle_counter, query, memory)
                            .1
                            .expect("must generate intermediate witness");

                    Some((reads, writes, PrecompileCyclesWitness::ECMul(round_witness)))
                } else {
                    let _ = ecmul::ecmul_function::<M, B>(monotonic_cycle_counter, query, memory);

                    None
                }
            }
            PrecompileAddress::EcPairing => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) = ecpairing::ecpairing_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    )
                    .1
                    .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::ECPairing(round_witness),
                    ))
                } else {
                    let _ = ecpairing::ecpairing_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::Modexp => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        modexp::modexp_function::<M, B>(monotonic_cycle_counter, query, memory)
                            .1
                            .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Modexp(round_witness),
                    ))
                } else {
                    let _ = modexp::modexp_function::<M, B>(monotonic_cycle_counter, query, memory);

                    None
                }
            }
        }
    }

    fn finish_frame(&mut self, _panicked: bool) {
        // there are no revertable precompile yes, so we are ok
    }
}
