use std::fmt::Debug;

use crate::proof;
use crate::proof::{ConsistencyProof, InclusionProof};
use crate::Error;

/// Hash abstraction for the Merkle tree.
///
/// Defines the three operations required by the tree. The tree is fully
/// generic over this trait — callers provide the concrete hash
/// implementation.
///
/// # Model Mapping
///
/// | Trait method | Formal model (§1) | Operation                    |
/// |:-------------|:-------------------|:-----------------------------|
/// | [`leaf`]     | `H.leaf(d)`        | `H(0x00 \|\| data)`         |
/// | [`node`]     | `H.node(l, r)`     | `H(0x01 \|\| left \|\| right)` |
/// | [`empty`]    | `H.empty`          | `H("")`                      |
///
/// [`leaf`]: TreeHasher::leaf
/// [`node`]: TreeHasher::node
/// [`empty`]: TreeHasher::empty
///
/// # Domain Separation (C-DOMAIN)
///
/// Implementations **must** ensure `leaf(d) ≠ node(l, r)` for all inputs.
/// The standard approach is to prepend `0x00` for leaves and `0x01` for
/// interior nodes before hashing (RFC 9162 §2.1).
pub trait TreeHasher {
    /// The digest type produced by this hasher.
    ///
    /// Must be cheaply cloneable, comparable, and printable for debugging.
    type Digest: Clone + Eq + Debug;

    /// Hash a leaf entry: `H(0x00 || data)`.
    fn leaf(&self, data: &[u8]) -> Self::Digest;

    /// Hash two child nodes: `H(0x01 || left || right)`.
    fn node(&self, left: &Self::Digest, right: &Self::Digest) -> Self::Digest;

    /// Hash of the empty string: `H("")`. Root of an empty tree.
    fn empty(&self) -> Self::Digest;
}

/// A dense, append-only, left-filled Merkle tree (RFC 9162 §2.1).
///
/// The tree is parameterized by a [`TreeHasher`] that defines the hash
/// operations. It supports O(1) amortized appends via a frontier stack
/// and O(1) root extraction.
///
/// Leaf hashes are retained for proof generation. Size is derived from
/// `leaves.len()` — no separate counter. The formal model (§3.1) defines
/// an explicit size field on a minimal `LogState` that carries no leaf
/// history. This implementation extends that state with a leaves vec for
/// proof generation, making size derivable.
#[derive(Debug, Clone)]
pub struct Log<H: TreeHasher> {
    hasher: H,
    /// Stored leaf hashes for proof generation.
    leaves: Vec<H::Digest>,
    /// Frontier stack: roots of complete subtrees along the right edge.
    stack: Vec<H::Digest>,
}

impl<H: TreeHasher> Log<H> {
    /// Create a new empty log with the given hasher.
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            leaves: Vec::new(),
            stack: Vec::new(),
        }
    }

    /// Append a new entry to the log. Returns the 0-based leaf index.
    ///
    /// Uses the incremental stack-based algorithm from the formal model
    /// §3.2: push the leaf hash, then merge complete pairs by counting
    /// trailing ones in the pre-increment size.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        let hash = self.hasher.leaf(data);

        // Compute merge count from pre-append size (equivalent to the
        // formal model's count_trailing_ones(state.size) before
        // state.size += 1).
        let merge_count = count_trailing_ones(self.leaves.len() as u64);

        self.leaves.push(hash.clone());
        self.stack.push(hash);

        for _ in 0..merge_count {
            // Structure-guarded: merge_count is bounded by the number of
            // trailing 1-bits in the pre-append size, which guarantees
            // at least 2 elements on the stack for each merge iteration.
            // See: lib.rs § Panic Policy.
            let right = self.stack.pop().expect("stack underflow in merge");
            let left = self.stack.pop().expect("stack underflow in merge");
            self.stack.push(self.hasher.node(&left, &right));
        }

        (self.leaves.len() - 1) as u64
    }

    /// Current number of leaves in the log.
    #[must_use = "returns the current leaf count without modifying the log"]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Current root hash of the log.
    ///
    /// For an empty tree, returns `H.empty`. For a non-empty tree, folds
    /// the frontier stack right-to-left per §3.3.
    #[must_use = "returns the root hash without modifying the log"]
    pub fn root(&self) -> H::Digest {
        if self.leaves.is_empty() {
            return self.hasher.empty();
        }

        // Zero-alloc fold: iterate the stack in reverse, accumulating
        // node hashes from right to left.
        self.stack
            .iter()
            .rev()
            .cloned()
            .reduce(|acc, left| self.hasher.node(&left, &acc))
            // Structure-guarded: non-empty leaves guarantees non-empty stack.
            // See: lib.rs § Panic Policy.
            .expect("non-empty tree has non-empty stack")
    }

    /// Returns a reference to the hasher.
    pub fn hasher(&self) -> &H {
        &self.hasher
    }

    /// Returns the number of entries in the frontier stack.
    ///
    /// Used for testing invariant A-STACK: `stack_len() == popcount(size)`.
    #[cfg(test)]
    fn stack_len(&self) -> usize {
        self.stack.len()
    }

    /// Generate an inclusion proof for the leaf at `index` (formal model §4.2).
    ///
    /// The proof demonstrates that the leaf at `index` exists in the current
    /// tree. Verify with [`verify_inclusion`](crate::verify_inclusion).
    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof<H::Digest>, Error> {
        let size = self.size();
        if size == 0 {
            return Err(Error::EmptyTree);
        }
        if index >= size {
            return Err(Error::IndexOutOfBounds {
                index,
                tree_size: size,
            });
        }
        let path = proof::gen_path(&self.hasher, index as usize, &self.leaves);
        Ok(InclusionProof {
            index,
            tree_size: size,
            path,
        })
    }

    /// Generate a consistency proof from `old_size` to the current size
    /// (formal model §5.2).
    ///
    /// The proof demonstrates that the tree at `old_size` is a prefix of
    /// the current tree. Verify with
    /// [`verify_consistency`](crate::verify_consistency).
    pub fn consistency_proof(&self, old_size: u64) -> Result<ConsistencyProof<H::Digest>, Error> {
        let size = self.size();
        if size == 0 {
            return Err(Error::EmptyTree);
        }
        if old_size == 0 || old_size >= size {
            return Err(Error::InvalidOldSize {
                old_size,
                new_size: size,
            });
        }
        let path = proof::gen_subproof(&self.hasher, old_size as usize, &self.leaves, true);
        Ok(ConsistencyProof {
            old_size,
            new_size: size,
            path,
        })
    }
}

/// Largest power of 2 strictly less than n (formal model §2.2).
///
/// Defined for n > 1. Panics if n ≤ 1.
pub(crate) fn largest_pow2_lt(n: usize) -> usize {
    assert!(n > 1, "largest_pow2_lt requires n > 1, got {n}");
    // 2^(floor(log2(n - 1)))
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Count trailing one-bits in the binary representation of n.
fn count_trailing_ones(n: u64) -> u32 {
    (!n).trailing_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_largest_pow2_lt() {
        assert_eq!(largest_pow2_lt(2), 1);
        assert_eq!(largest_pow2_lt(3), 2);
        assert_eq!(largest_pow2_lt(4), 2);
        assert_eq!(largest_pow2_lt(5), 4);
        assert_eq!(largest_pow2_lt(6), 4);
        assert_eq!(largest_pow2_lt(7), 4);
        assert_eq!(largest_pow2_lt(8), 4);
        assert_eq!(largest_pow2_lt(9), 8);
        assert_eq!(largest_pow2_lt(15), 8);
        assert_eq!(largest_pow2_lt(16), 8);
        assert_eq!(largest_pow2_lt(17), 16);
    }

    #[test]
    fn test_count_trailing_ones() {
        assert_eq!(count_trailing_ones(0b0000), 0);
        assert_eq!(count_trailing_ones(0b0001), 1);
        assert_eq!(count_trailing_ones(0b0011), 2);
        assert_eq!(count_trailing_ones(0b0101), 1);
        assert_eq!(count_trailing_ones(0b0111), 3);
        assert_eq!(count_trailing_ones(0b1010), 0);
    }

    /// A-STACK (formal model §3.4): after each append, the frontier stack
    /// has exactly popcount(size) entries.
    #[test]
    fn a_stack_popcount_invariant() {
        struct SimpleHasher;
        impl TreeHasher for SimpleHasher {
            type Digest = u64;
            fn leaf(&self, data: &[u8]) -> u64 {
                data.iter().fold(0u64, |acc, &b| acc.wrapping_add(b as u64))
            }
            fn node(&self, left: &u64, right: &u64) -> u64 {
                left.wrapping_mul(31).wrapping_add(*right)
            }
            fn empty(&self) -> u64 {
                0
            }
        }

        let mut log = Log::new(SimpleHasher);
        for i in 0u64..64 {
            log.append(format!("leaf-{i}").as_bytes());
            let expected = log.size().count_ones() as usize;
            assert_eq!(
                log.stack_len(),
                expected,
                "A-STACK failed at size={}: stack_len={}, popcount={}",
                log.size(),
                log.stack_len(),
                expected
            );
        }
    }
}
