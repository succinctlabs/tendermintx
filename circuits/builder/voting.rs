//! CometBFT's MaxTotalVotingPower = int64(math.MaxInt64) / 8
//! https://github.com/cometbft/cometbft/blob/eb51aa722e75939157a788ebe0f6b62aeffd0e5d/types/validator_set.go#L25
//! When summing the voting power of all validators, the total voting power will not overflow a u64.
//! When multiplying the total voting power by a small factor c < 16, the result will not overflow a u64.
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::Variable;
use plonky2x::prelude::{BoolVariable, CircuitBuilder, Field, PlonkParameters};

pub trait TendermintVoting {
    // Sums the voting power of all validators.
    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        nb_enabled_validators: Variable,
    ) -> U64Variable;

    /// Assert the enabled voting power > threshold * total voting power.
    #[must_use]
    fn is_voting_power_greater_than_threshold<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        validator_enabled: &[BoolVariable],
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintVoting for CircuitBuilder<L, D> {
    // Computes the total voting power from the first nb_enabled_validators.
    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        nb_enabled_validators: Variable,
    ) -> U64Variable {
        // Note: This can be made more efficient by implementing the add_many_u32 gate in plonky2x.
        let zero = self.zero();
        let mut total = self.zero();

        let mut is_enabled = self._true();
        for i in 0..validator_voting_power.len() {
            let idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));

            // If at_end, then the rest of the leaves (including this one) are disabled.
            let at_end = self.is_equal(idx, nb_enabled_validators);
            let not_at_end = self.not(at_end);
            is_enabled = self.and(not_at_end, is_enabled);

            // If enabled, add the voting power to the total.
            let val = self.select(is_enabled, validator_voting_power[i], zero);
            total = self.add(total, val)
        }
        total
    }

    // in_group specifies which validators to accumulate the voting power from.
    fn is_voting_power_greater_than_threshold<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        in_group: &[BoolVariable],
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable {
        let zero = self.constant::<U64Variable>(0);

        let mut accumulated_voting_power = self.constant::<U64Variable>(0);
        // Accumulate the voting power from the enabled validators.
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let select_voting_power = self.select(in_group[i], validator_voting_power[i], zero);
            accumulated_voting_power = self.add(accumulated_voting_power, select_voting_power);
        }

        let scaled_accumulated = self.mul(accumulated_voting_power, *threshold_denominator);
        let scaled_threshold = self.mul(*total_voting_power, *threshold_numerator);

        // Return accumulated_voting_power > total_vp * (threshold_numerator / threshold_denominator).
        self.gt(scaled_accumulated, scaled_threshold)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::env;

    use plonky2x::prelude::DefaultBuilder;

    use super::*;

    const VALIDATOR_SET_SIZE_MAX: usize = 4;

    #[test]
    fn test_accumulate_voting_power() {
        env::set_var("RUST_LOG", "info");
        env_logger::try_init().unwrap_or_default();

        let test_cases = [
            // voting power, enabled, pass
            (vec![10i64, 10i64, 10i64, 10i64], [1, 1, 1, 0], true),
            (vec![10i64, 10i64, 10i64, 10i64], [1, 1, 1, 1], true),
            (
                vec![4294967296000i64, 4294967296i64, 10i64, 10i64],
                [1, 0, 0, 0],
                true,
            ),
            (
                vec![4294967296000i64, 4294967296000i64, 4294967296000i64, 0i64],
                [1, 1, 0, 0],
                false,
            ),
            (
                vec![4294967296000i64, 4294967296000i64, 4294967296000i64, 0i64],
                [0, 0, 0, 0],
                false,
            ),
        ];

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let mut validator_voting_power_vec = Vec::new();
        let mut validator_enabled_vec = Vec::new();
        for _ in 0..VALIDATOR_SET_SIZE_MAX {
            validator_voting_power_vec.push(builder.read::<U64Variable>());
            validator_enabled_vec.push(builder.read::<BoolVariable>());
        }
        let total_voting_power = builder.read::<U64Variable>();
        let threshold_numerator = builder.read::<U64Variable>();
        let threshold_denominator = builder.read::<U64Variable>();
        let result = builder.is_voting_power_greater_than_threshold::<VALIDATOR_SET_SIZE_MAX>(
            &validator_voting_power_vec,
            &validator_enabled_vec,
            &total_voting_power,
            &threshold_numerator,
            &threshold_denominator,
        );
        builder.write(result);

        let circuit = builder.build();

        for test_case in test_cases {
            let mut input = circuit.input();

            let mut total_vp = 0;
            for i in 0..VALIDATOR_SET_SIZE_MAX {
                let voting_power = test_case.0[i];
                total_vp += voting_power;
                input.write::<U64Variable>(voting_power as u64);
                // If test_case.1[i] == 1, the test should pass.
                input.write::<BoolVariable>(test_case.1[i] == 1);
            }
            input.write::<U64Variable>(total_vp as u64);
            input.write::<U64Variable>(2);
            input.write::<U64Variable>(3);

            let (_, mut output) = circuit.prove(&input);
            assert_eq!(output.read::<BoolVariable>(), test_case.2);
        }
    }
}
