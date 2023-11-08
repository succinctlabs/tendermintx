// is taken from tendermint-rs (if that is the case).
/*
* Mocking comet-bft proof logic in Rust
* TODO: Upstream to tendermint-rs
*/

use std::cell::RefCell;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle_encoding::hex;
pub use tendermint::block::Header;
pub use tendermint::merkle::Hash;
use tendermint::validator::Set as TendermintValidatorSet;
/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use tendermint::{
    block::{Commit, CommitSig},
    merkle::MerkleHash,
    validator::Info,
    vote::Power,
    vote::{ValidatorIndex, Vote},
};
use tendermint_proto::types::{BlockId as RawBlockId, Data as RawData};
use tendermint_proto::version::Consensus as RawConsensusVersion;
use tendermint_proto::Protobuf;

/// Compute leaf hashes for arbitrary byte vectors.
/// The leaves of the tree are the bytes of the given byte vectors in
/// the given order.
pub fn hash_all_leaves<H>(byte_vecs: &[impl AsRef<[u8]>]) -> Vec<Hash>
where
    H: MerkleHash + Default,
{
    let mut _hasher = H::default();
    let hashed_leaves = byte_vecs
        .iter()
        .map(|b| leaf_hash::<Sha256>(b.as_ref()))
        .collect();
    hashed_leaves
}

#[derive(Debug, Deserialize)]
pub struct DataCommitmentResponse {
    pub result: DataCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DataCommitment {
    pub data_commitment: String,
}

#[derive(Debug, Deserialize)]
pub struct SignedBlockResponse {
    pub result: SignedBlock,
}

#[derive(Debug, Deserialize)]
pub struct HeaderResponse {
    pub result: WrappedHeader,
}

#[derive(Debug, Deserialize)]
pub struct WrappedHeader {
    pub header: Header,
}

// Note: Implementations of ValidatorSet and SignedBlock differ in tendermint-rs and comet-bft
/// Validator set contains a vector of validators
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Info>,
    pub proposer: Option<Info>,
    pub total_voting_power: Option<Power>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct SignedBlock {
    /// Block header
    pub header: Header,

    /// Transaction data
    pub data: RawData,

    /// Commit
    pub commit: Commit,

    /// Validator set
    pub validator_set: ValidatorSet,
}

// Note: Matches the implementation in tendermint-rs, need to add PR to tendermint-rs to support proofs
// https://github.com/tendermint/tendermint/blob/35581cf54ec436b8c37fabb43fdaa3f48339a170/crypto/merkle/proof.go#L35-L236
#[derive(Clone)]
pub struct Proof {
    pub total: u64,
    pub index: u64,
    pub leaf_hash: Hash,
    pub aunts: Vec<Hash>,
}

#[derive(Clone)]
pub struct ProofNode {
    pub hash: Hash,
    pub left: Option<Rc<RefCell<ProofNode>>>,
    pub right: Option<Rc<RefCell<ProofNode>>>,
    pub parent: Option<Rc<RefCell<ProofNode>>>,
}

impl Proof {
    pub fn new(total: u64, index: u64, leaf_hash: Hash, aunts: Vec<Hash>) -> Self {
        Proof {
            total,
            index,
            leaf_hash,
            aunts,
        }
    }

    pub fn compute_root_hash(&self) -> Option<Hash> {
        compute_hash_from_aunts(self.index, self.total, self.leaf_hash, self.aunts.clone())
    }

    pub fn verify(&self, root_hash: &Hash, leaf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let leaf_hash = leaf_hash::<Sha256>(leaf);
        println!("leaf_hash: {:?}", String::from_utf8(hex::encode(leaf_hash)));
        if self.leaf_hash != leaf_hash {
            return Err(format!(
                "invalid leaf hash: wanted {:?} got {:?}",
                hex::encode(leaf_hash),
                hex::encode(self.leaf_hash)
            )
            .into());
        }
        let computed_hash = self
            .compute_root_hash()
            .expect("failed to compute root hash");
        if computed_hash != *root_hash {
            return Err(format!(
                "invalid root hash: wanted {:?} got {:?}",
                hex::encode(root_hash),
                hex::encode(computed_hash)
            )
            .into());
        }
        Ok(())
    }
}

impl ProofNode {
    fn new(
        hash: Hash,
        parent: Option<Rc<RefCell<ProofNode>>>,
        left: Option<Rc<RefCell<ProofNode>>>,
        right: Option<Rc<RefCell<ProofNode>>>,
    ) -> Self {
        ProofNode {
            hash,
            parent,
            left,
            right,
        }
    }

    fn flatten_aunts(&self) -> Vec<Hash> {
        let mut inner_hashes = Vec::new();
        let mut current_node = Some(Rc::new(RefCell::new(self.clone())));

        while let Some(node) = current_node {
            // Separate this into two steps to avoid holding onto a borrow across loop iterations
            let (left, right) = {
                let node_borrowed = node.borrow();
                (node_borrowed.left.clone(), node_borrowed.right.clone())
            };

            match (&left, &right) {
                (Some(left_node), _) => inner_hashes.push(left_node.borrow().hash),
                (_, Some(right_node)) => inner_hashes.push(right_node.borrow().hash),
                _ => {}
            }

            // Now update current_node
            current_node = node.borrow().parent.clone();
        }

        inner_hashes
    }
}

pub fn compute_hash_from_proof(enc_leaf: &[u8], path: &Vec<bool>, aunts: &[Hash]) -> Option<Hash> {
    let mut hash_so_far = leaf_hash::<Sha256>(enc_leaf);
    for i in 0..path.len() {
        hash_so_far = if path[i] {
            inner_hash::<Sha256>(aunts[i], hash_so_far)
        } else {
            inner_hash::<Sha256>(hash_so_far, aunts[i])
        };
    }
    Some(hash_so_far)
}

pub fn compute_hash_from_aunts(
    index: u64,
    total: u64,
    leaf_hash: Hash,
    inner_hashes: Vec<Hash>,
) -> Option<Hash> {
    if index >= total || total == 0 {
        return None;
    }
    match total {
        0 => panic!("Cannot call compute_hash_from_aunts() with 0 total"),
        1 => {
            if !inner_hashes.is_empty() {
                return None;
            }
            Some(leaf_hash)
        }
        _ => {
            if inner_hashes.is_empty() {
                return None;
            }
            let num_left = get_split_point(total as usize) as u64;
            if index < num_left {
                let left_hash = compute_hash_from_aunts(
                    index,
                    num_left,
                    leaf_hash,
                    inner_hashes[..inner_hashes.len() - 1].to_vec(),
                );
                match left_hash {
                    None => return None,
                    Some(hash) => {
                        return Some(inner_hash::<Sha256>(
                            hash,
                            inner_hashes[inner_hashes.len() - 1],
                        ))
                    }
                }
            }
            let right_hash = compute_hash_from_aunts(
                index - num_left,
                total - num_left,
                leaf_hash,
                inner_hashes[..inner_hashes.len() - 1].to_vec(),
            );
            right_hash.map(|hash| inner_hash::<Sha256>(inner_hashes[inner_hashes.len() - 1], hash))
        }
    }
}

pub fn proofs_from_byte_slices(items: Vec<Vec<u8>>) -> (Hash, Vec<Proof>) {
    let (trails, root) = trails_from_byte_slices(items.clone());
    let root_hash = root.borrow().hash;
    let mut proofs = Vec::new();

    for (i, trail) in trails.into_iter().enumerate() {
        proofs.push(Proof::new(
            items.len() as u64,
            i as u64,
            trail.borrow().hash,
            trail.borrow().flatten_aunts(),
        ));
    }

    (root_hash, proofs)
}

// Create trail from byte slice to root
fn trails_from_byte_slices(
    items: Vec<Vec<u8>>,
) -> (Vec<Rc<RefCell<ProofNode>>>, Rc<RefCell<ProofNode>>) {
    match items.len() {
        0 => {
            let node = ProofNode::new(empty_hash(), None, None, None);
            (vec![], Rc::new(RefCell::new(node)))
        }
        1 => {
            let node = Rc::new(RefCell::new(ProofNode::new(
                leaf_hash::<Sha256>(&items[0]),
                None,
                None,
                None,
            )));

            (vec![Rc::clone(&node)], Rc::clone(&node))
        }
        _ => {
            let k = get_split_point(items.len());
            let (lefts, left_root) = trails_from_byte_slices(items[..k].to_vec());
            let (rights, right_root) = trails_from_byte_slices(items[k..].to_vec());

            let root_hash = inner_hash::<Sha256>(left_root.borrow().hash, right_root.borrow().hash);
            let root = Rc::new(RefCell::new(ProofNode::new(root_hash, None, None, None)));

            {
                let mut left_root_borrowed = (*left_root).borrow_mut();
                left_root_borrowed.parent = Some(Rc::clone(&root));
                left_root_borrowed.right = Some(Rc::clone(&right_root));
            }
            {
                let mut right_root_borrowed = (*right_root).borrow_mut();
                right_root_borrowed.parent = Some(Rc::clone(&root));
                right_root_borrowed.left = Some(Rc::clone(&left_root));
            }

            let trails = [lefts, rights].concat();

            (trails, root)
        }
    }
}

pub fn get_split_point(length: usize) -> usize {
    if length < 1 {
        panic!("Trying to split a tree with size < 1")
    }
    let bitlen = (length as f64).log2() as usize;
    let k = 1 << bitlen;
    if k == length {
        k >> 1
    } else {
        k
    }
}

fn empty_hash() -> Hash {
    Sha256::digest([])
        .to_vec()
        .try_into()
        .expect("slice with incorrect length")
}

pub fn leaf_hash<H>(leaf: &[u8]) -> Hash
where
    H: MerkleHash + Default,
{
    let mut hasher = H::default();
    hasher.leaf_hash(leaf)
}

pub fn inner_hash<H>(left: Hash, right: Hash) -> Hash
where
    H: MerkleHash + Default,
{
    let mut hasher = H::default();
    hasher.inner_hash(left, right)
}

pub fn generate_proofs_from_header(h: &Header) -> (Hash, Vec<Proof>) {
    let fields_bytes = vec![
        Protobuf::<RawConsensusVersion>::encode_vec(h.version),
        h.chain_id.clone().encode_vec(),
        h.height.encode_vec(),
        h.time.encode_vec(),
        Protobuf::<RawBlockId>::encode_vec(h.last_block_id.unwrap_or_default()),
        h.last_commit_hash.unwrap_or_default().encode_vec(),
        h.data_hash.unwrap_or_default().encode_vec(),
        h.validators_hash.encode_vec(),
        h.next_validators_hash.encode_vec(),
        h.consensus_hash.encode_vec(),
        h.app_hash.clone().encode_vec(),
        h.last_results_hash.unwrap_or_default().encode_vec(),
        h.evidence_hash.unwrap_or_default().encode_vec(),
        h.proposer_address.encode_vec(),
    ];

    proofs_from_byte_slices(fields_bytes)
}

pub fn generate_proofs_from_block_id(
    id: &tendermint::block::Id,
) -> (tendermint::merkle::Hash, Vec<Proof>) {
    let fields_bytes = vec![id.hash.encode_vec(), id.part_set_header.hash.encode_vec()];

    proofs_from_byte_slices(fields_bytes)
}

// Gets the vote struct: https://github.com/informalsystems/tendermint-rs/blob/c2b5c9e01eab1c740598aa14375a7453f3bfa436/light-client-verifier/src/operations/voting_power.rs#L202-L238
pub fn get_vote_from_commit_sig(
    commit_sig: &CommitSig,
    validator_index: ValidatorIndex,
    commit: &Commit,
) -> Option<Vote> {
    // Cast the raw commit sig to a commit sig
    let (validator_address, timestamp, signature, block_id) = match commit_sig {
        CommitSig::BlockIdFlagAbsent { .. } => return None,
        CommitSig::BlockIdFlagCommit {
            validator_address,
            timestamp,
            signature,
        } => (
            validator_address,
            timestamp,
            signature,
            Some(commit.block_id),
        ),
        CommitSig::BlockIdFlagNil {
            validator_address,
            timestamp,
            signature,
        } => (validator_address, timestamp, signature, None),
    };

    Some(Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: commit.height,
        round: commit.round,
        block_id,
        timestamp: Some(*timestamp),
        validator_address: *validator_address,
        validator_index,
        signature: signature.clone(),
        extension: Default::default(),
        extension_signature: None,
    })
}

/// Determines if a valid skip is possible between start_block and target_block.
pub fn is_valid_skip(start_block: &SignedBlock, target_block: &SignedBlock) -> bool {
    let threshold = 1_f64 / 3_f64;

    let mut shared_voting_power = 0;

    let target_block_validator_set = TendermintValidatorSet::new(
        target_block.validator_set.validators.clone(),
        target_block.validator_set.proposer.clone(),
    );
    let start_block_validator_set = TendermintValidatorSet::new(
        start_block.validator_set.validators.clone(),
        start_block.validator_set.proposer.clone(),
    );

    let target_block_total_voting_power = target_block_validator_set.total_voting_power().value();

    let start_block_validators = start_block_validator_set.validators();

    let mut start_block_idx = 0;
    let start_block_num_validators = start_block_validators.len();

    // Exit if we have already reached the threshold
    // TODO: Confirm this is resilient by testing many different cases.
    while target_block_total_voting_power as f64 * threshold > shared_voting_power as f64
        && start_block_idx < start_block_num_validators
    {
        if let Some(target_block_validator) =
            target_block_validator_set.validator(start_block_validators[start_block_idx].address)
        {
            // Confirm that the validator has signed on block_2
            for sig in target_block.commit.signatures.iter() {
                if sig.validator_address().is_some()
                    && sig.validator_address().unwrap() == target_block_validator.address
                {
                    // Add the shared voting power to the validator
                    shared_voting_power += target_block_validator.power();
                }
            }
        }
        start_block_idx += 1;
    }

    target_block_total_voting_power as f64 * threshold <= shared_voting_power as f64
}
