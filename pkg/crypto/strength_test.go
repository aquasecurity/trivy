package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestAssessStrength(t *testing.T) {
	tests := []struct {
		name          string
		oid           string
		size          int
		subgroupSize  int
		curve         string
		wantClassical *int
		wantCategory  *int
	}{
		{name: "RSA-1024", oid: "1.2.840.113549.1.1.1", size: 1024, wantClassical: new(80), wantCategory: new(0)},
		{name: "RSA-2048", oid: "1.2.840.113549.1.1.1", size: 2048, wantClassical: new(112), wantCategory: new(0)},
		{name: "RSA-3072", oid: "1.2.840.113549.1.1.1", size: 3072, wantClassical: new(128), wantCategory: new(0)},
		{name: "RSA-4096", oid: "1.2.840.113549.1.1.1", size: 4096, wantClassical: new(152), wantCategory: new(0)},
		{name: "RSA-6144", oid: "1.2.840.113549.1.1.1", size: 6144, wantClassical: new(176), wantCategory: new(0)},
		{name: "RSA-8192", oid: "1.2.840.113549.1.1.1", size: 8192, wantClassical: new(200), wantCategory: new(0)},
		{
			// A key size between the listed ones has no estimate, rather than the one of a
			// neighbor.
			name:         "RSA with an uncovered key size",
			oid:          "1.2.840.113549.1.1.1",
			size:         2047,
			wantCategory: new(0),
		},
		{
			name:         "RSA without a key size",
			oid:          "1.2.840.113549.1.1.1",
			wantCategory: new(0),
		},
		{name: "EC-P-224", oid: "1.2.840.10045.2.1", curve: "P-224", wantClassical: new(112), wantCategory: new(0)},
		{name: "EC-P-256", oid: "1.2.840.10045.2.1", curve: "P-256", wantClassical: new(128), wantCategory: new(0)},
		{name: "EC-P-384", oid: "1.2.840.10045.2.1", curve: "P-384", wantClassical: new(192), wantCategory: new(0)},
		{name: "EC-P-521", oid: "1.2.840.10045.2.1", curve: "P-521", wantClassical: new(256), wantCategory: new(0)},
		{
			name:         "EC with an uncovered curve",
			oid:          "1.2.840.10045.2.1",
			curve:        "secp256k1",
			wantCategory: new(0),
		},
		{name: "DSA (1024, 160)", oid: "1.2.840.10040.4.1", size: 1024, subgroupSize: 160, wantClassical: new(80), wantCategory: new(0)},
		{name: "DSA (2048, 224)", oid: "1.2.840.10040.4.1", size: 2048, subgroupSize: 224, wantClassical: new(112), wantCategory: new(0)},
		{name: "DSA (2048, 256)", oid: "1.2.840.10040.4.1", size: 2048, subgroupSize: 256, wantClassical: new(112), wantCategory: new(0)},
		{name: "DSA (3072, 256)", oid: "1.2.840.10040.4.1", size: 3072, subgroupSize: 256, wantClassical: new(128), wantCategory: new(0)},
		{
			// FIPS 186 does not pair an L of 2048 with an N of 160.
			name: "DSA with an uncovered pair",
			oid:  "1.2.840.10040.4.1",
			size: 2048, subgroupSize: 160,
			wantCategory: new(0),
		},
		{
			name:         "DSA without a subgroup size",
			oid:          "1.2.840.10040.4.1",
			size:         2048,
			wantCategory: new(0),
		},
		{name: "Ed25519", oid: "1.3.101.112", wantClassical: new(128), wantCategory: new(0)},
		{name: "ML-DSA-44", oid: "2.16.840.1.101.3.4.3.17", wantCategory: new(2)},
		{name: "ML-DSA-65", oid: "2.16.840.1.101.3.4.3.18", wantCategory: new(3)},
		{name: "ML-DSA-87", oid: "2.16.840.1.101.3.4.3.19", wantCategory: new(5)},
		{
			// The strength of a signature depends on the key of the issuer.
			name:         "signature algorithm",
			oid:          "1.2.840.113549.1.1.11",
			wantCategory: new(0),
		},
		{
			// RSASSA-PSS is left out of the catalog.
			name: "algorithm outside the catalog",
			oid:  "1.2.840.113549.1.1.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The identity comes from DescribeAlgorithm, so the parameters are encoded the way
			// the parser encodes them. The algorithm carries levels of its own, which the
			// assessment replaces without writing to the algorithm, as an in-memory cache may
			// hold it.
			info := crypto.DescribeAlgorithm(tt.oid, tt.size, tt.subgroupSize, tt.curve)
			original := info.Algorithm
			original.ClassicalSecurityLevel = new(1)
			original.NISTQuantumSecurityLevel = new(6)
			assets := []ftypes.CryptoAsset{{CryptoAssetInfo: info}}

			crypto.AssessStrength(assets)
			assert.Equal(t, tt.wantClassical, assets[0].Algorithm.ClassicalSecurityLevel)
			assert.Equal(t, tt.wantCategory, assets[0].Algorithm.NISTQuantumSecurityLevel)
			require.NoError(t, assets[0].Validate())

			assert.Equal(t, new(1), original.ClassicalSecurityLevel)
			assert.Equal(t, new(6), original.NISTQuantumSecurityLevel)
		})
	}

	t.Run("assets that are not algorithms identified by an OID", func(t *testing.T) {
		rsa := crypto.DescribeAlgorithm("1.2.840.113549.1.1.1", 2048, 0, "")
		withoutDetails := rsa
		withoutDetails.Algorithm = nil
		otherMethod := rsa.Clone()
		otherMethod.Identity.Method = ftypes.CryptoMethodSHA256
		otherKind := rsa.Clone()
		otherKind.Kind = ftypes.CryptoKindKey

		assets := []ftypes.CryptoAsset{
			{CryptoAssetInfo: otherKind},
			{CryptoAssetInfo: withoutDetails},
			{CryptoAssetInfo: otherMethod},
		}
		want := []ftypes.CryptoAsset{assets[0].Clone(), assets[1].Clone(), assets[2].Clone()}

		crypto.AssessStrength(assets)
		assert.Equal(t, want, assets)
	})
}
