package digest

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDigest(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		data []byte
		want string
	}{
		{
			name: "SHA256",
			alg:  SHA256,
			data: []byte("hello"),
			want: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name: "SHA1",
			alg:  SHA1,
			data: []byte("hello"),
			want: "sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		},
		{
			name: "empty input",
			alg:  SHA256,
			data: []byte(""),
			want: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h = sha256.New()
			if tt.alg == SHA1 {
				h = sha1.New()
			}
			h.Write(tt.data)
			got := NewDigest(tt.alg, h)
			assert.Equal(t, Digest(tt.want), got)
		})
	}
}

func TestNewDigestFromString(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		hash string
		want string
	}{
		{
			name: "SHA256 hex string",
			alg:  SHA256,
			hash: "abcdef1234567890",
			want: "sha256:abcdef1234567890",
		},
		{
			name: "MD5 hex string",
			alg:  MD5,
			hash: "d41d8cd98f00b204e9800998ecf8427e",
			want: "md5:d41d8cd98f00b204e9800998ecf8427e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDigestFromString(tt.alg, tt.hash)
			assert.Equal(t, Digest(tt.want), got)
		})
	}
}

func TestDigest_Algorithm(t *testing.T) {
	tests := []struct {
		name   string
		digest Digest
		want   Algorithm
	}{
		{
			name:   "SHA256 digest",
			digest: "sha256:abcdef",
			want:   SHA256,
		},
		{
			name:   "SHA1 digest",
			digest: "sha1:abcdef",
			want:   SHA1,
		},
		{
			name:   "SHA512 digest",
			digest: "sha512:abcdef",
			want:   SHA512,
		},
		{
			name:   "MD5 digest",
			digest: "md5:abcdef",
			want:   MD5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.digest.Algorithm())
		})
	}
}

func TestDigest_Encoded(t *testing.T) {
	tests := []struct {
		name   string
		digest Digest
		want   string
	}{
		{
			name:   "SHA256 digest",
			digest: "sha256:abcdef1234567890",
			want:   "abcdef1234567890",
		},
		{
			name:   "SHA1 digest",
			digest: "sha1:aaf4c61ddcc5e8a2",
			want:   "aaf4c61ddcc5e8a2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.digest.Encoded())
		})
	}
}

func TestDigest_String(t *testing.T) {
	d := Digest("sha256:abcdef")
	assert.Equal(t, "sha256:abcdef", d.String())
}

func TestDigest_sepIndex(t *testing.T) {
	tests := []struct {
		name   string
		digest Digest
		want   int
	}{
		{
			name:   "normal digest",
			digest: "sha256:abcdef",
			want:   6,
		},
		{
			name:   "no colon returns 0",
			digest: "nocolon",
			want:   0,
		},
		{
			name:   "empty string returns 0",
			digest: "",
			want:   0,
		},
		{
			name:   "colon at start returns 0",
			digest: ":abcdef",
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.digest.sepIndex())
		})
	}
}

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		alg  Algorithm
		want string
	}{
		{SHA1, "sha1"},
		{SHA256, "sha256"},
		{SHA512, "sha512"},
		{MD5, "md5"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.alg.String())
		})
	}
}

func TestCalcSHA1(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "known input",
			data: []byte("hello"),
			want: "sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		},
		{
			name: "empty input",
			data: []byte(""),
			want: "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := CalcSHA1(r)
			require.NoError(t, err)
			assert.Equal(t, Digest(tt.want), got)
		})
	}
}

func TestCalcSHA1_SeekReset(t *testing.T) {
	data := []byte("test data")
	r := bytes.NewReader(data)

	_, err := CalcSHA1(r)
	require.NoError(t, err)

	// reader should be reset to start after CalcSHA1
	buf := make([]byte, len(data))
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf)
}

func TestCalcSHA256(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "known input",
			data: []byte("hello"),
			want: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name: "empty input",
			data: []byte(""),
			want: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalcSHA256(tt.data)
			assert.Equal(t, Digest(tt.want), got)
		})
	}
}

func TestCalcSHA256FromReader(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "known input",
			data: []byte("hello"),
			want: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name: "empty input",
			data: []byte(""),
			want: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := CalcSHA256FromReader(r)
			require.NoError(t, err)
			assert.Equal(t, Digest(tt.want), got)
		})
	}
}

func TestCalcSHA256FromReader_SeekReset(t *testing.T) {
	data := []byte("test data")
	r := bytes.NewReader(data)

	_, err := CalcSHA256FromReader(r)
	require.NoError(t, err)

	// reader should be reset to start after CalcSHA256FromReader
	buf := make([]byte, len(data))
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf)
}
