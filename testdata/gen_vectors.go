//go:build ignore

// Generates golden test vectors for cross-language parity verification.
//
// Usage:
//
//	go run testdata/gen_vectors.go > testdata/vectors.json
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cyphrme/malt"
)

const (
	fnvOffset = 0xcbf29ce484222325
	fnvPrime  = 0x00000100000001B3
)

func fnv1a(data []byte) [8]byte {
	hash := uint64(fnvOffset)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= fnvPrime
	}
	var result [8]byte
	binary.BigEndian.PutUint64(result[:], hash)
	return result
}

type SimpleHasher struct{}

func (SimpleHasher) Leaf(data []byte) [8]byte {
	buf := make([]byte, 1+len(data))
	buf[0] = 0x00
	copy(buf[1:], data)
	return fnv1a(buf)
}

func (SimpleHasher) Node(left, right [8]byte) [8]byte {
	var buf [1 + 8 + 8]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[9:], right[:])
	return fnv1a(buf[:])
}

func (SimpleHasher) Empty() [8]byte {
	return fnv1a(nil)
}

func h(d [8]byte) string {
	return hex.EncodeToString(d[:])
}

func hs(ds [][8]byte) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = h(d)
	}
	return out
}

type RootEntry struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

type InclusionEntry struct {
	TreeSize uint64   `json:"tree_size"`
	Index    uint64   `json:"index"`
	LeafHash string   `json:"leaf_hash"`
	Path     []string `json:"path"`
}

type ConsistencyEntry struct {
	OldSize uint64   `json:"old_size"`
	NewSize uint64   `json:"new_size"`
	Path    []string `json:"path"`
}

type Vectors struct {
	Hasher      string             `json:"hasher"`
	LeafFormat  string             `json:"leaf_format"`
	Roots       []RootEntry        `json:"roots"`
	Inclusion   []InclusionEntry   `json:"inclusion_proofs"`
	Consistency []ConsistencyEntry `json:"consistency_proofs"`
}

func buildLog(n uint64) *malt.Log[[8]byte] {
	log := malt.New[[8]byte](SimpleHasher{})
	for i := range n {
		log.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return log
}

func main() {
	hasher := SimpleHasher{}
	v := Vectors{
		Hasher:     "FNV-1a-64",
		LeafFormat: "leaf-{i}",
	}

	// Roots for sizes 0..17
	for n := uint64(0); n <= 17; n++ {
		log := buildLog(n)
		v.Roots = append(v.Roots, RootEntry{
			Size: n,
			Root: h(log.Root()),
		})
	}

	// Inclusion proofs: representative pairs
	inclusionCases := [][2]uint64{
		{1, 0},
		{2, 0}, {2, 1},
		{4, 0}, {4, 2}, {4, 3},
		{8, 0}, {8, 3}, {8, 5}, {8, 7},
		{17, 0}, {17, 8}, {17, 16},
	}
	for _, tc := range inclusionCases {
		n, m := tc[0], tc[1]
		log := buildLog(n)
		proof, _ := log.InclusionProof(m)
		leafHash := hasher.Leaf([]byte(fmt.Sprintf("leaf-%d", m)))
		v.Inclusion = append(v.Inclusion, InclusionEntry{
			TreeSize: n,
			Index:    m,
			LeafHash: h(leafHash),
			Path:     hs(proof.Path),
		})
	}

	// Consistency proofs: representative pairs
	consistencyCases := [][2]uint64{
		{1, 2},
		{1, 4}, {2, 4}, {3, 4},
		{1, 8}, {4, 8}, {6, 8},
		{1, 17}, {8, 17}, {15, 17},
	}
	for _, tc := range consistencyCases {
		m, n := tc[0], tc[1]
		log := buildLog(n)
		proof, _ := log.ConsistencyProof(m)
		v.Consistency = append(v.Consistency, ConsistencyEntry{
			OldSize: m,
			NewSize: n,
			Path:    hs(proof.Path),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
