# malt

A generic, zero-dependency Merkle Append-Only Log Tree conforming to
[RFC 9162 §2.1][rfc] (Certificate Transparency v2.0).

## Features

- **O(1) amortized appends** via a frontier stack.
- **Inclusion proofs** — prove a specific entry exists in the log.
- **Consistency proofs** — prove an older log is a prefix of a newer one.
- **Zero dependencies** — callers supply their own hash via the
  [`TreeHasher`] trait.

## Usage

```rust
use malt::{Log, TreeHasher, verify_inclusion, verify_consistency};

// Implement TreeHasher for your hash function, then:
let mut log = Log::new(my_hasher);
log.append(b"first entry");
log.append(b"second entry");
let root = log.root();

// Inclusion proof for leaf 0:
let proof = log.inclusion_proof(0).unwrap();
let ok = verify_inclusion(&my_hasher, &leaf_hash, &proof, &root);

// Consistency proof from size 1 → current:
let cproof = log.consistency_proof(1).unwrap();
let ok = verify_consistency(&my_hasher, &cproof, &old_root, &root);
```

## TreeHasher Contract

Implement three operations on your hash type:

| Operation | Signature                                  | Semantics               |
| :-------- | :----------------------------------------- | :---------------------- |
| `leaf`    | `fn leaf(&self, data: &[u8]) -> D`         | `H(0x00 \|\| data)`     |
| `node`    | `fn node(&self, left: &D, right: &D) -> D` | `H(0x01 \|\| l \|\| r)` |
| `empty`   | `fn empty(&self) -> D`                     | `H("")`                 |

The `0x00`/`0x01` prefix enforces **domain separation** — leaf hashes
cannot collide with interior node hashes (RFC 9162 §2.1).

## Formal Model

The implementation follows a [formal domain model][model] based on initial
algebra with equational laws. Key invariants verified by the test suite:

- **A-EQUIV** — incremental append equals batch construction.
- **A-STACK** — frontier stack size equals `popcount(n)`.
- **I-SOUND** — inclusion proofs always verify.
- **K-SOUND** — consistency proofs always verify.

A [Go implementation][go] with identical semantics is maintained in the
same repository.

## License

[MIT](LICENSE)

[rfc]: https://www.rfc-editor.org/rfc/rfc9162#section-2.1
[model]: https://github.com/Cyphrme/malt/blob/main/docs/models/verifiable-log.md
[go]: https://pkg.go.dev/github.com/cyphrme/malt
