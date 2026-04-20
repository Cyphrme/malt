# MALT — Merkle Append-Only Log Tree

A generic, zero-dependency implementation of the Merkle tree construction from
[RFC 9162 §2.1][rfc] (Certificate Transparency v2.0). Dual implementations in
**Go** and **Rust** with identical semantics.

- **Go docs:** [pkg.go.dev/github.com/cyphrme/malt](https://pkg.go.dev/github.com/cyphrme/malt)
- **Rust docs:** [docs.rs/malt](https://docs.rs/malt)
- **Crate:** [crates.io/crates/malt](https://crates.io/crates/malt)

## What It Does

MALT provides an append-only log backed by a dense, left-filled Merkle tree.
Given any hash function, it supports:

- **O(1) amortized appends** via a frontier stack.
- **Inclusion proofs** — prove a specific entry exists in the log.
- **Consistency proofs** — prove that an older log is a prefix of a newer one
  (the append-only property).

The tree is fully parameterized by a hash abstraction (`TreeHasher` trait/interface).
Callers supply their own hash — MALT imposes no cryptographic opinion. This makes
it suitable for both single-algorithm and multi-algorithm (e.g. MHMR) usage.

## Structure

```
malt/
├── go.mod          # Go module: github.com/cyphrme/malt
├── malt.go         # Core tree: Log, Append, Root
├── proof.go        # Inclusion & consistency proofs + verification
├── error.go        # Sentinel errors
├── malt_test.go    # Go tests
├── parity_test.go  # Cross-language golden vector tests
├── testdata/
│   └── vectors.json # Shared golden test vectors
├── LICENSE         # MIT
└── rs/
    ├── Cargo.toml  # Rust crate: malt
    ├── LICENSE     # MIT
    ├── src/
    │   ├── lib.rs
    │   ├── tree.rs
    │   ├── proof.rs
    │   └── error.rs
    └── tests/
        ├── common/
        │   └── mod.rs
        ├── correctness.rs
        ├── proofs.rs
        └── parity.rs  # Cross-language golden vector tests
```

Go lives at the repository root for clean `go get` import paths. Rust lives in
`rs/` and publishes to crates.io independently.

## Usage

### Go

```go
import "github.com/cyphrme/malt"

// Implement malt.TreeHasher[D] for your hash, then:
log := malt.New[MyDigest](myHasher)
log.Append([]byte("first entry"))
log.Append([]byte("second entry"))
root := log.Root()

// Inclusion proof for leaf 0:
proof, err := log.InclusionProof(0)
ok := malt.VerifyInclusion(myHasher, leafHash, proof, root)

// Consistency proof from size 1 → current:
cproof, err := log.ConsistencyProof(1)
ok = malt.VerifyConsistency(myHasher, cproof, oldRoot, root)
```

```sh
go get github.com/cyphrme/malt@latest
```

### Rust

```rust
use malt::{Log, TreeHasher, verify_inclusion, verify_consistency};

// Implement malt::TreeHasher for your hash, then:
let mut log = Log::new(my_hasher);
log.append(b"first entry");
log.append(b"second entry");
let root = log.root();

// Inclusion proof for leaf 0:
let proof = log.inclusion_proof(0)?;
let ok = verify_inclusion(&my_hasher, &leaf_hash, &proof, &root);

// Consistency proof from size 1 → current:
let cproof = log.consistency_proof(1)?;
let ok = verify_consistency(&my_hasher, &cproof, &old_root, &root);
```

```toml
[dependencies]
malt = "0.1"
```

## TreeHasher Contract

Both implementations require the caller to provide three operations:

| Operation | Signature (Go)          | Semantics               |
| :-------- | :---------------------- | :---------------------- |
| `Leaf`    | `Leaf(data []byte) D`   | `H(0x00 \|\| data)`     |
| `Node`    | `Node(left, right D) D` | `H(0x01 \|\| l \|\| r)` |
| `Empty`   | `Empty() D`             | `H("")`                 |

The `0x00`/`0x01` prefix convention enforces **domain separation** — leaf
hashes can never collide with interior node hashes (RFC 9162 §2.1).

## Formal Model

The implementation follows a [formal domain model][model] based on initial
algebra (inductive type definition) with equational laws. Key invariants
verified by the test suites:

- **A-EQUIV** — incremental append produces the same root as batch construction.
- **A-STACK** — frontier stack size equals `popcount(n)` after `n` appends.
- **I-SOUND** — correctly generated inclusion proofs always verify.
- **K-SOUND** — correctly generated consistency proofs always verify.
- **I-SIZE / K-SIZE** — proof sizes are logarithmically bounded.

Both implementations share an identical FNV-1a test hasher and assert against
a shared set of [golden test vectors](testdata/vectors.json) — roots, inclusion
proof paths, and consistency proof paths — ensuring cross-language parity.

## License

[MIT](LICENSE)

[rfc]: https://www.rfc-editor.org/rfc/rfc9162#section-2.1
[model]: docs/models/verifiable-log.md
