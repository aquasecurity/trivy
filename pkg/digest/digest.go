package digest

import (
	"crypto/sha1" // nolint
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/xerrors"
)

type Algorithm string

func (a Algorithm) String() string {
	return string(a)
}

// supported digest types
const (
	SHA1   Algorithm = "sha1"   // sha1 with hex encoding (lower case only)
	SHA256 Algorithm = "sha256" // sha256 with hex encoding (lower case only)
)

// Digest allows simple protection of hex formatted digest strings, prefixed by their algorithm.
//
// The following is an example of the contents of Digest types:
//
//	sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc
type Digest string

// NewDigest returns a Digest from alg and a hash.Hash object.
func NewDigest(alg Algorithm, h hash.Hash) Digest {
	return Digest(fmt.Sprintf("%s:%x", alg, h.Sum(nil)))
}

func (d Digest) Algorithm() Algorithm {
	return Algorithm(d[:d.sepIndex()])
}

func (d Digest) Encoded() string {
	return string(d[d.sepIndex()+1:])
}

func (d Digest) String() string {
	return string(d)
}

func (d Digest) sepIndex() int {
	i := strings.Index(string(d), ":")
	if i < 0 {
		i = 0
	}
	return i
}

func CalcSHA1(r io.ReadSeeker) (Digest, error) {
	defer r.Seek(0, io.SeekStart)

	h := sha1.New() // nolint
	if _, err := io.Copy(h, r); err != nil {
		return "", xerrors.Errorf("unable to calculate sha1 digest: %w", err)
	}

	return NewDigest(SHA1, h), nil
}

func CalcSHA256(r io.ReadSeeker) (Digest, error) {
	defer r.Seek(0, io.SeekStart)

	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", xerrors.Errorf("unable to calculate sha256 digest: %w", err)
	}

	return NewDigest(SHA256, h), nil
}
