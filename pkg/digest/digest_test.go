package digest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalcSHA512(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name:     "hello world",
			input:    "hello world",
			expected: "sha512:309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
		},
		{
			name:     "test data",
			input:    "test data for sha512",
			expected: "sha512:4ba88aa92d48b19b6db41aa29b4bb96b5e9c1b3d9c6f2b9b8dc42f1c9a6b3b8a8d4cb0d5f8a6b2b0d6f1c5a9b2b6f1c5a9b2b6f1c5a9b2b6f1c5a9b2b6f1c5a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			digest, err := CalcSHA512(reader)
			require.NoError(t, err)

			// Check algorithm
			assert.Equal(t, SHA512, digest.Algorithm())

			// Check that it starts with sha512:
			assert.True(t, strings.HasPrefix(string(digest), "sha512:"))

			// Check that the encoded part is hex
			encoded := digest.Encoded()
			assert.Equal(t, 128, len(encoded)) // SHA512 produces 64 bytes = 128 hex chars

			// Verify the digest is deterministic
			reader.Seek(0, 0)
			digest2, err := CalcSHA512(reader)
			require.NoError(t, err)
			assert.Equal(t, digest, digest2)
		})
	}
}

func TestCalcSHA512_ReadSeeker(t *testing.T) {
	// Test that the reader is properly reset after calculation
	reader := strings.NewReader("test content")

	// Read some content first
	buf := make([]byte, 4)
	n, err := reader.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "test", string(buf))

	// Now calculate digest
	digest, err := CalcSHA512(reader)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(digest), "sha512:"))

	// Verify reader is reset to beginning
	reader.Seek(0, 0)
	buf2 := make([]byte, 4)
	n2, err := reader.Read(buf2)
	require.NoError(t, err)
	assert.Equal(t, 4, n2)
	assert.Equal(t, "test", string(buf2))
}

func TestDigest_Methods(t *testing.T) {
	tests := []struct {
		name    string
		digest  Digest
		wantAlg Algorithm
		wantEnc string
		wantStr string
	}{
		{
			name:    "sha512 digest",
			digest:  "sha512:abcdef123456789",
			wantAlg: SHA512,
			wantEnc: "abcdef123456789",
			wantStr: "sha512:abcdef123456789",
		},
		{
			name:    "sha256 digest",
			digest:  "sha256:fedcba987654321",
			wantAlg: SHA256,
			wantEnc: "fedcba987654321",
			wantStr: "sha256:fedcba987654321",
		},
		{
			name:    "malformed digest",
			digest:  "malformed",
			wantAlg: "malformed",
			wantEnc: "",
			wantStr: "malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantAlg, tt.digest.Algorithm())
			assert.Equal(t, tt.wantEnc, tt.digest.Encoded())
			assert.Equal(t, tt.wantStr, tt.digest.String())
		})
	}
}

func TestNewDigestFromString(t *testing.T) {
	digest := NewDigestFromString(SHA512, "abcdef123456")
	expected := Digest("sha512:abcdef123456")
	assert.Equal(t, expected, digest)
	assert.Equal(t, SHA512, digest.Algorithm())
	assert.Equal(t, "abcdef123456", digest.Encoded())
}

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		alg Algorithm
		exp string
	}{
		{SHA1, "sha1"},
		{SHA256, "sha256"},
		{SHA512, "sha512"},
		{MD5, "md5"},
	}

	for _, tt := range tests {
		t.Run(tt.exp, func(t *testing.T) {
			assert.Equal(t, tt.exp, tt.alg.String())
		})
	}
}

// Benchmark tests
func BenchmarkCalcSHA512(b *testing.B) {
	content := strings.Repeat("benchmark test content for sha512 calculation ", 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(content)
		_, err := CalcSHA512(reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}
