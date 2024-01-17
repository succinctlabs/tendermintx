use plonky2x::frontend::merkle::tendermint::TendermintMerkleTree;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder,
    CircuitVariable, Field, PlonkParameters, Variable,
};

use crate::consts::{
    BLOCK_HEIGHT_INDEX, HEADER_PROOF_DEPTH, PROTOBUF_VARINT_SIZE_BYTES, VARINT_BYTES_LENGTH_MAX,
};

pub trait TendermintHeader<L: PlonkParameters<D>, const D: usize> {
    /// Get the path to a leaf in the Tendermint header.
    fn get_path_to_leaf(&mut self, index: usize)
        -> ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>;

    /// Serializes an int64 as a protobuf varint.
    fn marshal_int64_varint(
        &mut self,
        num: &U64Variable,
    ) -> [ByteVariable; VARINT_BYTES_LENGTH_MAX];

    /// Encodes the marshalled height into a BytesVariable<11> that can be hashed according to the
    /// Tendermint spec. Prepends 0x00 byte as leaf prefix and 0x08 byte for varint encoding.
    fn leaf_encode_marshalled_varint(
        &mut self,
        marshalled_varint: &BytesVariable<9>,
    ) -> BytesVariable<11>;

    /// Verifies the block height against the header.
    fn verify_block_height(
        &mut self,
        header: Bytes32Variable,
        proof: &ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
        height: &U64Variable,
        encoded_height_byte_length: U32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> TendermintHeader<L, D> for CircuitBuilder<L, D> {
    /// Get the path to a leaf in the Tendermint header.
    fn get_path_to_leaf(
        &mut self,
        index: usize,
    ) -> ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH> {
        let false_t = self._false();
        let true_t = self._true();

        // The path to the leaf in a Tendermint header.
        let mut path = Vec::new();
        let mut curr_idx = index;
        for _ in 0..HEADER_PROOF_DEPTH {
            if curr_idx % 2 == 0 {
                path.push(false_t);
            } else {
                path.push(true_t);
            }
            curr_idx /= 2;
        }

        ArrayVariable::<BoolVariable, HEADER_PROOF_DEPTH>::new(path)
    }

    fn marshal_int64_varint(
        &mut self,
        value: &U64Variable,
    ) -> [ByteVariable; VARINT_BYTES_LENGTH_MAX] {
        // TODO: Assert the value is less than 2^63 - 1.
        let zero = self.zero::<Variable>();
        let one = self.one::<Variable>();
        let two = self.constant::<Variable>(L::Field::from_canonical_usize(2));

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        // Note: need to be careful regarding U64 and I64 differences.
        let value_bits = self.to_le_bits(*value);

        // Check that the MSB of the voting power is zero.
        self.assert_is_equal(value_bits[value_bits.len() - 1].variable, zero);

        // The septet (7 bit) payloads  of the "varint".
        let septets = (0..VARINT_BYTES_LENGTH_MAX)
            .map(|i| {
                let mut base = one;
                let mut septet = self.zero::<Variable>();
                for j in 0..7 {
                    let bit = value_bits[i * 7 + j];

                    let bit_val = self.mul(base, bit.variable);
                    septet = self.add(septet, bit_val);

                    base = self.mul(base, two)
                }
                septet
            })
            .collect::<Vec<_>>();

        // Calculates whether the septet is not zero.
        let is_zero_septets = (0..VARINT_BYTES_LENGTH_MAX)
            .map(|i| self.is_equal(septets[i], zero))
            .collect::<Vec<_>>();

        // Calculates the index of the last non-zero septet.
        let mut last_seen_non_zero_septet_idx = self.zero();

        for i in 0..VARINT_BYTES_LENGTH_MAX {
            // Cast with from_variables_unsafe since is_zero_septets[i] is always 0 or 1.
            let is_nonzero_septet =
                BoolVariable::from_variables_unsafe(&[self.sub(one, is_zero_septets[i].variable)]);
            let idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));
            last_seen_non_zero_septet_idx =
                self.select(is_nonzero_septet, idx, last_seen_non_zero_septet_idx);
        }

        let mut res = [self.zero(); VARINT_BYTES_LENGTH_MAX];

        // If the index of a septet is elss than the last non-zero septet, set the most significant
        // bit of the byte to 1 and copy the septet bits into the lower 7 bits. Otherwise, still
        // copy the bit but the set the most significant bit to zero.
        for i in 0..VARINT_BYTES_LENGTH_MAX {
            // If the index is less than the last non-zero septet index, `diff` will be in
            // [0, VARINT_BYTES_LENGTH_MAX).
            let idx = self.constant(L::Field::from_canonical_usize(i + 1));
            let diff = self.sub(last_seen_non_zero_septet_idx, idx);

            // Calculates whether we've seen at least one `diff` in [0, VARINT_BYTES_LENGTH_MAX).
            let mut is_lt_last_non_zero_septet_idx = self._false();
            for j in 0..VARINT_BYTES_LENGTH_MAX {
                let candidate_idx = self.constant(L::Field::from_canonical_usize(j));
                let is_candidate = self.is_equal(diff, candidate_idx);
                is_lt_last_non_zero_septet_idx =
                    self.or(is_lt_last_non_zero_septet_idx, is_candidate);
            }

            let mut buffer = [self._false(); 8];
            // Copy septet bits into the buffer.
            for j in 0..7 {
                let bit = value_bits[i * 7 + j];
                buffer[j] = bit;
            }

            // Set the most significant bit of the byte to 1 if the index is less than the last
            // non-zero septet index.
            buffer[7] = is_lt_last_non_zero_septet_idx;

            // Reverse the buffer to BE since ByteVariable interprets variables as BE
            buffer.reverse();

            res[i] = ByteVariable::from_variables_unsafe(
                &buffer.iter().map(|x| x.variable).collect::<Vec<Variable>>(),
            );
        }

        res
    }

    fn leaf_encode_marshalled_varint(
        &mut self,
        marshalled_varint: &BytesVariable<9>,
    ) -> BytesVariable<11> {
        // Prepends a 0x00 byte for the leaf prefix then a 0x08 byte for the protobuf varint encoding.
        let mut encoded_marshalled_varint =
            self.constant::<BytesVariable<2>>([0x00, 0x08]).0.to_vec();
        encoded_marshalled_varint.extend_from_slice(&marshalled_varint.0);
        BytesVariable(encoded_marshalled_varint.try_into().unwrap())
    }

    fn verify_block_height(
        &mut self,
        header: Bytes32Variable,
        proof: &ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
        height: &U64Variable,
        encoded_height_byte_length: U32Variable,
    ) {
        let block_height_path = self.get_path_to_leaf(BLOCK_HEIGHT_INDEX);

        // Marshal the block height into bytes, then encode it as a leaf.
        let encoded_height = self.marshal_int64_varint(height);
        let encoded_height = self.leaf_encode_marshalled_varint(&BytesVariable(encoded_height));

        // Extend encoded_height to 64 bytes. Variable SHA256 requires the input length in bytes to
        // be equal to the specified MAX_NUM_CHUNKS * 64.
        let mut encoded_height_extended = encoded_height.0.to_vec();
        for _i in PROTOBUF_VARINT_SIZE_BYTES + 1..64 {
            encoded_height_extended.push(self.constant::<ByteVariable>(0u8));
        }

        // Add 1 to the encoded height byte length to account for the 0x00 byte.
        let one_u32 = self.constant::<U32Variable>(1);
        let encoded_height_byte_length = self.add(encoded_height_byte_length, one_u32);

        // Hash the encoded height.
        let leaf_hash =
            self.curta_sha256_variable(&encoded_height_extended, encoded_height_byte_length);

        // Verify the computed block height against the header.
        let computed_header = self.get_root_from_merkle_proof_hashed_leaf::<HEADER_PROOF_DEPTH>(
            proof,
            &block_height_path,
            leaf_hash,
        );

        self.assert_is_equal(computed_header, header);
    }
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use plonky2x::prelude::DefaultBuilder;

    use super::*;

    #[test]
    fn test_marshal_int64_varint() {
        env_logger::try_init().unwrap_or_default();
        // These are test cases generated from `celestia-core`.
        //
        // allZerosPubkey := make(ed25519.PubKey, ed25519.PubKeySize)
        // votingPower := int64(9999999999999)
        // validator := NewValidator(allZerosPubkey, votingPower)
        // fmt.Println(validator.Bytes()[37:])
        //
        // The tuples hold the form: (voting_power_i64, voting_power_varint_bytes).
        let test_cases = [
            (1i64, vec![1u8]),
            (3804i64, vec![220u8, 29u8]),
            (1234567890i64, vec![210, 133, 216, 204, 4]),
            (38957235239i64, vec![167, 248, 160, 144, 145, 1]),
            (9999999999999i64, vec![255, 191, 202, 243, 132, 163, 2]),
            (
                724325643436111i64,
                vec![207, 128, 183, 165, 211, 216, 164, 1],
            ),
            (
                9223372036854775807i64,
                vec![255, 255, 255, 255, 255, 255, 255, 255, 127],
            ),
        ];

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let voting_power_variable = builder.read::<U64Variable>();
        let result = builder.marshal_int64_varint(&voting_power_variable);
        builder.write::<BytesVariable<VARINT_BYTES_LENGTH_MAX>>(BytesVariable(result));

        let circuit = builder.build();

        for test_case in test_cases {
            let mut input = circuit.input();
            input.write::<U64Variable>(test_case.0 as u64);
            let (_, mut output) = circuit.prove(&input);

            let expected_bytes = test_case.1;

            println!("Voting Power: {:?}", test_case.0);
            println!("Expected Varint Encoding (Bytes): {:?}", expected_bytes);

            let output_bytes = output.read::<BytesVariable<VARINT_BYTES_LENGTH_MAX>>();

            for i in 0..expected_bytes.len() {
                assert_eq!(output_bytes[i], expected_bytes[i]);
            }
        }
    }

    #[test]
    fn test_encode_varint() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        let height = builder.constant::<U64Variable>(3804);

        let encoded_height = builder.marshal_int64_varint(&height);
        let encoded_height = builder.leaf_encode_marshalled_varint(&BytesVariable(encoded_height));
        builder.watch(&encoded_height, "encoded_height");

        let circuit = builder.build();

        let input = circuit.input();
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        println!("Verified proof");
    }
}
