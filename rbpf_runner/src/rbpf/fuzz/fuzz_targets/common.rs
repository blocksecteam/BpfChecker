use std::mem::size_of;

use arbitrary::{Arbitrary, Unstructured};

use solana_rbpf::vm::Config;

#[derive(Debug)]
pub struct ConfigTemplate {
    max_call_depth: usize,
    instruction_meter_checkpoint_distance: usize,
    noop_instruction_ratio: f64,
    enable_stack_frame_gaps: bool,
    enable_symbol_and_section_labels: bool,
    disable_unresolved_symbols_at_runtime: bool,
    sanitize_user_provided_values: bool,
    encrypt_environment_registers: bool,
    disable_deprecated_load_instructions: bool,
    reject_callx_r10: bool,
    dynamic_stack_frames: bool,
    enable_sdiv: bool,
    optimize_rodata: bool,
}

impl<'a> Arbitrary<'a> for ConfigTemplate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let bools = u16::arbitrary(u)?;
        Ok(ConfigTemplate {
            max_call_depth: usize::from(u8::arbitrary(u)?) + 1, // larger is unreasonable + must be non-zero
            instruction_meter_checkpoint_distance: usize::from(u16::arbitrary(u)?), // larger is unreasonable
            noop_instruction_ratio: match f64::arbitrary(u)?.rem_euclid(1.) {
                f if !f.is_normal() => 0.0,
                f => f,
            }, // map it between 0 and 1, drop NaN
            enable_stack_frame_gaps: bools & (1 << 0) != 0,
            enable_symbol_and_section_labels: bools & (1 << 1) != 0,
            disable_unresolved_symbols_at_runtime: bools & (1 << 2) != 0,
            sanitize_user_provided_values: bools & (1 << 3) != 0,
            encrypt_environment_registers: bools & (1 << 4) != 0,
            disable_deprecated_load_instructions: bools & (1 << 5) != 0,
            reject_callx_r10: bools & (1 << 6) != 0,
            dynamic_stack_frames: bools & (1 << 7) != 0,
            enable_sdiv: bools & (1 << 8) != 0,
            optimize_rodata: bools & (1 << 9) != 0,
        })
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (
            size_of::<u8>() + size_of::<u16>() + size_of::<f64>() + size_of::<u16>(),
            None,
        )
    }
}

impl From<ConfigTemplate> for Config {
    fn from(template: ConfigTemplate) -> Self {
        match template {
            ConfigTemplate {
                max_call_depth,
                instruction_meter_checkpoint_distance,
                noop_instruction_ratio,
                enable_stack_frame_gaps,
                enable_symbol_and_section_labels,
                disable_unresolved_symbols_at_runtime,
                sanitize_user_provided_values,
                encrypt_environment_registers,
                disable_deprecated_load_instructions,
                reject_callx_r10,
                dynamic_stack_frames,
                enable_sdiv,
                optimize_rodata,
            } => Config {
                max_call_depth,
                enable_stack_frame_gaps,
                instruction_meter_checkpoint_distance,
                enable_symbol_and_section_labels,
                disable_unresolved_symbols_at_runtime,
                noop_instruction_ratio,
                sanitize_user_provided_values,
                encrypt_environment_registers,
                disable_deprecated_load_instructions,
                reject_callx_r10,
                dynamic_stack_frames,
                enable_sdiv,
                optimize_rodata,
                ..Default::default()
            },
        }
    }
}
