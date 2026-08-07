package types_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cryptotest"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestCryptoDescriptorString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		desc types.CryptoDescriptor
		want string
	}{
		{
			name: "certificate",
			desc: cryptotest.CertificateDescriptor(),
			want: "certificate:sha256:" + strings.Repeat("a", 64),
		},
		{
			name: "public key",
			desc: cryptotest.PublicKeyDescriptor(),
			want: "key:public:spki-sha256:" + strings.Repeat("b", 64),
		},
		{
			name: "private key",
			desc: cryptotest.PrivateKeyDescriptor(),
			want: "key:private:spki-sha256:" + strings.Repeat("b", 64),
		},
		{
			name: "encrypted private key",
			desc: cryptotest.EncryptedPrivateKeyDescriptor(),
			want: "key:private:encrypted-pkcs8-sha256:" + strings.Repeat("b", 64),
		},
		{
			name: "algorithm without parameters",
			desc: cryptotest.AlgorithmDescriptor(),
			want: "algorithm:oid:1.2.840.113549.1.1.1",
		},
		{
			name: "algorithm key size",
			desc: types.CryptoDescriptor{
				Kind: types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{
					Method:     types.CryptoMethodOID,
					Value:      "1.2.840.113549.1.1.1",
					Parameters: "key-size=2048",
				},
			},
			want: "algorithm:oid:1.2.840.113549.1.1.1:key-size%3D2048",
		},
		{
			name: "algorithm parameters are escaped",
			desc: types.CryptoDescriptor{
				Kind: types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{
					Method:     types.CryptoMethodOID,
					Value:      "1.2.840.10045.2.1",
					Parameters: "curve=P-256:key",
				},
			},
			want: "algorithm:oid:1.2.840.10045.2.1:curve%3DP-256%3Akey",
		},
		{
			name: "algorithm parameter space",
			desc: types.CryptoDescriptor{
				Kind: types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{
					Method:     types.CryptoMethodOID,
					Value:      "1.2.840.10045.2.1",
					Parameters: "curve=P 256",
				},
			},
			want: "algorithm:oid:1.2.840.10045.2.1:curve%3DP+256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.desc.String())
		})
	}
}

func TestCryptoDescriptorValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		desc    types.CryptoDescriptor
		wantErr string
	}{
		{name: "certificate", desc: cryptotest.CertificateDescriptor()},
		{name: "public key", desc: cryptotest.PublicKeyDescriptor()},
		{name: "private key", desc: cryptotest.PrivateKeyDescriptor()},
		{name: "algorithm", desc: cryptotest.AlgorithmDescriptor()},
		{
			name:    "unknown kind",
			desc:    types.CryptoDescriptor{Kind: "unknown"},
			wantErr: `unknown asset kind "unknown"`,
		},
		{
			name:    "missing key type",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindKey, Identity: cryptotest.PublicKeyDescriptor().Identity},
			wantErr: `unknown key type ""`,
		},
		{
			name:    "unknown key type",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindKey, KeyType: "secret", Identity: cryptotest.PublicKeyDescriptor().Identity},
			wantErr: `unknown key type "secret"`,
		},
		{
			name:    "key type on certificate",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindCertificate, KeyType: types.CryptoKeyTypePublic, Identity: cryptotest.CertificateDescriptor().Identity},
			wantErr: `certificate descriptor must not contain key type "public"`,
		},
		{
			name:    "key type on algorithm",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, KeyType: types.CryptoKeyTypePrivate, Identity: cryptotest.AlgorithmDescriptor().Identity},
			wantErr: `algorithm descriptor must not contain key type "private"`,
		},
		{
			name:    "wrong certificate identification method",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindCertificate, Identity: cryptotest.PublicKeyDescriptor().Identity},
			wantErr: `certificate descriptor requires identification method "sha256"`,
		},
		{
			name: "wrong public key identification method",
			desc: types.CryptoDescriptor{
				Kind: types.CryptoKindKey, KeyType: types.CryptoKeyTypePublic,
				Identity: types.CryptoIdentity{Method: types.CryptoMethodEncryptedPKCS8SHA256, Value: strings.Repeat("a", 64)},
			},
			wantErr: `public key descriptor requires identification method "spki-sha256"`,
		},
		{
			name: "wrong private key identification method",
			desc: types.CryptoDescriptor{
				Kind: types.CryptoKindKey, KeyType: types.CryptoKeyTypePrivate,
				Identity: types.CryptoIdentity{Method: types.CryptoMethodSHA256, Value: strings.Repeat("a", 64)},
			},
			wantErr: `private key descriptor has unknown identification method "sha256"`,
		},
		{
			name:    "wrong algorithm identification method",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: cryptotest.CertificateDescriptor().Identity},
			wantErr: `algorithm descriptor requires identification method "oid"`,
		},
		{
			name:    "uppercase hash",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindCertificate, Identity: types.CryptoIdentity{Method: types.CryptoMethodSHA256, Value: strings.Repeat("A", 64)}},
			wantErr: "identification value must be 64 lowercase hexadecimal characters",
		},
		{
			name:    "short hash",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindCertificate, Identity: types.CryptoIdentity{Method: types.CryptoMethodSHA256, Value: strings.Repeat("a", 63)}},
			wantErr: "identification value must be 64 lowercase hexadecimal characters",
		},
		{
			name:    "non hexadecimal hash",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindCertificate, Identity: types.CryptoIdentity{Method: types.CryptoMethodSHA256, Value: strings.Repeat("g", 64)}},
			wantErr: "identification value must be 64 lowercase hexadecimal characters",
		},
		{
			name:    "non canonical OID arc",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.02.840.113549"}},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name:    "invalid OID first arc",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "3.1.1"}},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name:    "one OID arc",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1"}},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name: "OID root zero second arc boundary",
			desc: types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "0.39"}},
		},
		{
			name:    "OID root zero second arc above boundary",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "0.40"}},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name: "OID root one second arc boundary",
			desc: types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.39"}},
		},
		{
			name:    "OID root one second arc above boundary",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.40"}},
			wantErr: "identification value must be a canonical OID",
		},
		{
			name: "OID root two unrestricted second arc",
			desc: types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "2.40"}},
		},
		{
			name: "OID arc larger than machine integer",
			desc: types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "2.184467440737095516160"}},
		},
		{
			name:    "parameters on certificate",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindCertificate, Identity: types.CryptoIdentity{Method: types.CryptoMethodSHA256, Value: strings.Repeat("a", 64), Parameters: "curve=P-256"}},
			wantErr: "parameters are only valid for OID algorithm descriptors",
		},
		{
			name:    "parameters on key",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindKey, KeyType: types.CryptoKeyTypePublic, Identity: types.CryptoIdentity{Method: types.CryptoMethodSPKISHA256, Value: strings.Repeat("b", 64), Parameters: "key-size=2048"}},
			wantErr: "parameters are only valid for OID algorithm descriptors",
		},
		{
			name:    "zero key size parameter",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.2.3", Parameters: "key-size=0"}},
			wantErr: "key size parameter must be a canonical positive decimal",
		},
		{
			name:    "leading zero key size parameter",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.2.3", Parameters: "key-size=02048"}},
			wantErr: "key size parameter must be a canonical positive decimal",
		},
		{
			name:    "empty curve parameter",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.2.3", Parameters: "curve="}},
			wantErr: "curve parameter must not be empty",
		},
		{
			name:    "unknown parameter form",
			desc:    types.CryptoDescriptor{Kind: types.CryptoKindAlgorithm, Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.2.3", Parameters: "mode=GCM"}},
			wantErr: `unknown algorithm parameters "mode=GCM"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.desc.Validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCryptoDescriptorMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		desc    types.CryptoDescriptor
		want    string
		wantErr bool
	}{
		{
			name: "certificate",
			desc: cryptotest.CertificateDescriptor(),
			want: `"certificate:sha256:` + strings.Repeat("a", 64) + `"`,
		},
		{
			name: "algorithm parameters",
			desc: types.CryptoDescriptor{
				Kind:     types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{Method: types.CryptoMethodOID, Value: "1.2.840.113549.1.1.1", Parameters: "key-size=2048"},
			},
			want: `"algorithm:oid:1.2.840.113549.1.1.1:key-size%3D2048"`,
		},
		{
			name:    "invalid descriptor",
			desc:    types.CryptoDescriptor{Kind: "unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.desc.MarshalJSON()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestCryptoDescriptorUnmarshalJSON(t *testing.T) {
	t.Parallel()

	hash := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		in      string
		want    types.CryptoDescriptor
		wantErr string
	}{
		{
			name: "certificate",
			in:   `"certificate:sha256:` + hash + `"`,
			want: cryptotest.CertificateDescriptor(),
		},
		{
			name: "lowercase percent escape",
			in:   `"algorithm:oid:1.2.3:key-size%3d2048"`,
			want: types.CryptoDescriptor{
				Kind: types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{
					Method:     types.CryptoMethodOID,
					Value:      "1.2.3",
					Parameters: "key-size=2048",
				},
			},
		},
		{
			name: "escaped unreserved byte",
			in:   `"algorithm:oid:1.2.3:curve%3DP%2D256"`,
			want: types.CryptoDescriptor{
				Kind: types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{
					Method:     types.CryptoMethodOID,
					Value:      "1.2.3",
					Parameters: "curve=P-256",
				},
			},
		},
		{
			name: "raw plus is a space",
			in:   `"algorithm:oid:1.2.3:curve%3DP+256"`,
			want: types.CryptoDescriptor{
				Kind: types.CryptoKindAlgorithm,
				Identity: types.CryptoIdentity{
					Method:     types.CryptoMethodOID,
					Value:      "1.2.3",
					Parameters: "curve=P 256",
				},
			},
		},
		{
			name:    "empty",
			in:      `""`,
			wantErr: `unknown descriptor kind ""`,
		},
		{
			name:    "unknown kind",
			in:      `"secret:sha256:` + hash + `"`,
			wantErr: `unknown descriptor kind "secret"`,
		},
		{
			name:    "missing segment",
			in:      `"certificate:sha256"`,
			wantErr: "certificate descriptor must contain 3 segments",
		},
		{
			name:    "extra certificate segment",
			in:      `"certificate:sha256:` + hash + `:extra"`,
			wantErr: "certificate descriptor must contain 3 segments",
		},
		{
			name:    "extra key segment",
			in:      `"key:public:spki-sha256:` + hash + `:extra"`,
			wantErr: "key descriptor must contain 4 segments",
		},
		{
			name:    "extra algorithm segment",
			in:      `"algorithm:oid:1.2.3:key-size%3D2048:extra"`,
			wantErr: "algorithm descriptor must contain 3 or 4 segments",
		},
		{
			name:    "malformed short percent escape",
			in:      `"algorithm:oid:1.2.3:curve%3"`,
			wantErr: `invalid URL escape "%3"`,
		},
		{
			name:    "malformed non hexadecimal percent escape",
			in:      `"algorithm:oid:1.2.3:curve%XZ"`,
			wantErr: `invalid URL escape "%XZ"`,
		},
		{
			name:    "empty parameter segment",
			in:      `"algorithm:oid:1.2.3:"`,
			wantErr: "algorithm descriptor parameters must not be empty",
		},
		{
			name:    "non-string JSON",
			in:      `{}`,
			wantErr: "cannot unmarshal object into Go value of type string",
		},
		{
			name:    "invalid JSON",
			in:      `"certificate`,
			wantErr: "unexpected end of JSON input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got types.CryptoDescriptor
			err := got.UnmarshalJSON([]byte(tt.in))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
