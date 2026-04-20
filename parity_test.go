package malt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// Cross-language parity tests.
//
// These tests verify that the Go implementation produces identical output
// to the golden test vectors in testdata/vectors.json. The Rust
// implementation runs the same assertions against the same file,
// ensuring both implementations remain in lockstep.
// ---------------------------------------------------------------------------

type vectorFile struct {
	Hasher      string              `json:"hasher"`
	LeafFormat  string              `json:"leaf_format"`
	Roots       []rootVector        `json:"roots"`
	Inclusion   []inclusionVector   `json:"inclusion_proofs"`
	Consistency []consistencyVector `json:"consistency_proofs"`
}

type rootVector struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

type inclusionVector struct {
	TreeSize uint64   `json:"tree_size"`
	Index    uint64   `json:"index"`
	LeafHash string   `json:"leaf_hash"`
	Path     []string `json:"path"`
}

type consistencyVector struct {
	OldSize uint64   `json:"old_size"`
	NewSize uint64   `json:"new_size"`
	Path    []string `json:"path"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("failed to read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	return v
}

func hexDigest(d [8]byte) string {
	return hex.EncodeToString(d[:])
}

// TestParityRoots verifies roots against the golden vectors.
func TestParityRoots(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Roots {
		log := buildLog(tc.Size)
		got := hexDigest(log.Root())
		if got != tc.Root {
			t.Fatalf("root mismatch at size %d: got %s, want %s", tc.Size, got, tc.Root)
		}
	}
}

// TestParityInclusionProofs verifies inclusion proof paths against golden vectors.
func TestParityInclusionProofs(t *testing.T) {
	v := loadVectors(t)
	h := SimpleHasher{}
	for _, tc := range v.Inclusion {
		log := buildLog(tc.TreeSize)
		root := log.Root()
		proof, err := log.InclusionProof(tc.Index)
		if err != nil {
			t.Fatalf("size=%d index=%d: %v", tc.TreeSize, tc.Index, err)
		}

		// Verify path matches golden vector.
		if len(proof.Path) != len(tc.Path) {
			t.Fatalf("size=%d index=%d: path length %d, want %d",
				tc.TreeSize, tc.Index, len(proof.Path), len(tc.Path))
		}
		for i, got := range proof.Path {
			if hexDigest(got) != tc.Path[i] {
				t.Fatalf("size=%d index=%d: path[%d] = %s, want %s",
					tc.TreeSize, tc.Index, i, hexDigest(got), tc.Path[i])
			}
		}

		// Verify leaf hash matches.
		leafHash := h.Leaf([]byte(fmt.Sprintf("leaf-%d", tc.Index)))
		if hexDigest(leafHash) != tc.LeafHash {
			t.Fatalf("size=%d index=%d: leaf hash mismatch", tc.TreeSize, tc.Index)
		}

		// Verify the proof itself.
		if !VerifyInclusion(h, leafHash, proof, root) {
			t.Fatalf("size=%d index=%d: golden proof failed verification", tc.TreeSize, tc.Index)
		}
	}
}

// TestParityConsistencyProofs verifies consistency proof paths against golden vectors.
func TestParityConsistencyProofs(t *testing.T) {
	v := loadVectors(t)
	h := SimpleHasher{}
	for _, tc := range v.Consistency {
		log := buildLog(tc.NewSize)
		newRoot := log.Root()
		proof, err := log.ConsistencyProof(tc.OldSize)
		if err != nil {
			t.Fatalf("old=%d new=%d: %v", tc.OldSize, tc.NewSize, err)
		}

		// Verify path matches golden vector.
		if len(proof.Path) != len(tc.Path) {
			t.Fatalf("old=%d new=%d: path length %d, want %d",
				tc.OldSize, tc.NewSize, len(proof.Path), len(tc.Path))
		}
		for i, got := range proof.Path {
			if hexDigest(got) != tc.Path[i] {
				t.Fatalf("old=%d new=%d: path[%d] = %s, want %s",
					tc.OldSize, tc.NewSize, i, hexDigest(got), tc.Path[i])
			}
		}

		// Verify the proof itself.
		oldRoot := buildLog(tc.OldSize).Root()
		if !VerifyConsistency(h, proof, oldRoot, newRoot) {
			t.Fatalf("old=%d new=%d: golden proof failed verification", tc.OldSize, tc.NewSize)
		}
	}
}
