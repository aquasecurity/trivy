package digest_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
)

func TestNewDigest(t *testing.T) {
	h := sha256.New()
	_, err := h.Write([]byte("hello world"))
	require.NoError(t, err)

	got := digest.NewDigest(digest.SHA256, h)
	assert.Equal(t, digest.Digest("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"), got)
}

func TestNewDigest_EmptyHash(t *testing.T) {
	h := sha256.New() // no writes

	got := digest.NewDigest(digest.SHA256, h)
	assert.Equal(t, digest.Digest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), got)
}

func TestNewDigestFromString(t *testing.T) {
	got := digest.NewDigestFromString(digest.SHA256, "7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")
	assert.Equal(t, digest.Digest("sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc"), got)
}

func TestDigest_Parts(t *testing.T) {
	tests := []struct {
		name    string
		digest  digest.Digest
		wantAlg digest.Algorithm
		wantEnc string
		wantStr string
	}{
		{
			name:    "sha256 digest",
			digest:  "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantAlg: digest.SHA256,
			wantEnc: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantStr: "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:    "sha1 digest",
			digest:  "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
			wantAlg: digest.SHA1,
			wantEnc: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
			wantStr: "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
		},
		{
			name:    "no separator",
			digest:  "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantAlg: "",
			wantEnc: "94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantStr: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
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

func TestAlgorithm_String(t *testing.T) {
	assert.Equal(t, "sha256", digest.SHA256.String())
	assert.Equal(t, "sha1", digest.SHA1.String())
	assert.Equal(t, "sha512", digest.SHA512.String())
	assert.Equal(t, "md5", digest.MD5.String())
}

func TestCalcSHA256(t *testing.T) {
	got := digest.CalcSHA256([]byte("hello world"))
	assert.Equal(t, digest.Digest("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"), got)
}

func TestCalcSHA256_Empty(t *testing.T) {
	got := digest.CalcSHA256(nil)
	assert.Equal(t, digest.Digest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), got)
}

func TestCalcSHA1(t *testing.T) {
	r := bytes.NewReader([]byte("hello world"))

	got, err := digest.CalcSHA1(r)
	require.NoError(t, err)
	assert.Equal(t, digest.Digest("sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"), got)

	// The reader must be rewound so callers can read the content again.
	pos, err := r.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Zero(t, pos)
}

func TestCalcSHA256FromReader(t *testing.T) {
	r := bytes.NewReader([]byte("hello world"))

	got, err := digest.CalcSHA256FromReader(r)
	require.NoError(t, err)
	assert.Equal(t, digest.Digest("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"), got)

	// The reader must be rewound so callers can read the content again.
	pos, err := r.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Zero(t, pos)
}

func TestCalcSHA256FromReader_Empty(t *testing.T) {
	got, err := digest.CalcSHA256FromReader(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, digest.Digest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), got)
}

// errReadSeeker fails on Read. It deliberately does not embed another reader:
// embedding strings.Reader would also promote WriteTo, which io.Copy prefers
// over Read, and the injected error would never trigger.
type errReadSeeker struct{}

func (errReadSeeker) Read(_ []byte) (int, error) {
	return 0, assert.AnError
}

func (errReadSeeker) Seek(_ int64, _ int) (int64, error) {
	return 0, nil
}

func TestCalcSHA1_ReadError(t *testing.T) {
	_, err := digest.CalcSHA1(errReadSeeker{})
	require.ErrorContains(t, err, "unable to calculate sha1 digest")
}

func TestCalcSHA256FromReader_ReadError(t *testing.T) {
	_, err := digest.CalcSHA256FromReader(errReadSeeker{})
	require.ErrorContains(t, err, "unable to calculate sha256 digest")
}
