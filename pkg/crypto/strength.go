package crypto

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// strengthBasis is the published basis the security levels of an algorithm are assessed
// from. The levels themselves are assessed after caching by AssessStrength, so that a
// change to a basis applies without analyzing again.
//
// The levels are nominal estimates taken from NIST and RFC publications. They estimate the
// strength of an algorithm and its parameters, and are neither a guarantee for an
// implementation nor a statement of policy approval.
type strengthBasis struct {
	// nistCategory is the NIST post-quantum security category. It is nil for an algorithm
	// with no basis, which then gets neither level.
	nistCategory *int
	// classicalStrengths maps the canonical parameters of an asset to its classical strength
	// in bits. Parameters it does not list have no estimate.
	classicalStrengths map[string]int
}

// RSA, EC, DSA and EdDSA rest on integer factorization and discrete logarithms, which a
// sufficiently capable quantum computer breaks, as FIPS 204 section 1.2 discusses, so they
// meet none of the NIST categories.
var (
	// A signature algorithm has no classical strength, because the strength of a signature
	// is limited by the key that produced it, and that key belongs to the issuer, which a
	// certificate does not carry.
	signatureStrengthBasis = strengthBasis{
		nistCategory: new(0),
	}

	// RSA estimates for 2048 bits and above are the approximate maximum strengths in
	// NIST SP 800-56B Rev. 2, Appendix D, Table 4. RSA-1024 takes the nominal maximum of 80
	// from NIST SP 800-57 Part 1 Rev. 5, Table 2, whose row states at most 80 bits.
	rsaStrengthBasis = strengthBasis{
		nistCategory: new(0),
		classicalStrengths: map[string]int{
			"key-size=1024": 80,
			"key-size=2048": 112,
			"key-size=3072": 128,
			"key-size=4096": 152,
			"key-size=6144": 176,
			"key-size=8192": 200,
		},
	}

	// EC estimates are the ECC strength ranges in NIST SP 800-57 Part 1 Rev. 5, Table 2.
	ecStrengthBasis = strengthBasis{
		nistCategory: new(0),
		classicalStrengths: map[string]int{
			"curve=P-224": 112,
			"curve=P-256": 128,
			"curve=P-384": 192,
			"curve=P-521": 256,
		},
	}

	// DSA estimates depend on both L and N. They are the FFC entries of NIST SP 800-57
	// Part 1 Rev. 5, Table 2, and the DSA strengths in NIST SP 800-131A Rev. 2, Section 3.
	// The (1024, 160) value is the nominal maximum of the at-most-80 row.
	dsaStrengthBasis = strengthBasis{
		nistCategory: new(0),
		classicalStrengths: map[string]int{
			"key-size=1024,subgroup-size=160": 80,
			"key-size=2048,subgroup-size=224": 112,
			"key-size=2048,subgroup-size=256": 112,
			"key-size=3072,subgroup-size=256": 128,
		},
	}

	// Ed25519 has no parameters, and RFC 8032 section 8.5 puts its strength at about 128
	// bits.
	// See https://datatracker.ietf.org/doc/html/rfc8032#section-8.5
	ed25519StrengthBasis = strengthBasis{
		nistCategory: new(0),
		classicalStrengths: map[string]int{
			"": 128,
		},
	}
)

// mldsaStrengthBasis is the basis of an ML-DSA parameter set, which FIPS 204 assigns a NIST
// category without a classical strength to translate it into.
func mldsaStrengthBasis(category int) strengthBasis {
	return strengthBasis{
		nistCategory: new(category),
	}
}

// AssessStrength fills in the nominal security levels of algorithm assets from the basis
// the catalog holds for their OID. An OID with no basis gets neither level, and parameters
// the basis does not cover get no classical level. Levels the assets already carry are
// replaced, so that they come from the basis alone.
func AssessStrength(assets []ftypes.CryptoAsset) {
	for i := range assets {
		asset := &assets[i]
		if asset.Kind != ftypes.CryptoKindAlgorithm || asset.Algorithm == nil ||
			asset.Identity.Method != ftypes.CryptoMethodOID {
			continue
		}

		// The levels go to a copy of the algorithm, because an in-memory cache hands out
		// the algorithm it holds, and the cache keeps no levels.
		assessed := *asset.Algorithm
		assessed.ClassicalSecurityLevel, assessed.NISTQuantumSecurityLevel = securityLevels(asset.Identity)
		asset.Algorithm = &assessed
	}
}

// securityLevels assesses the levels of an algorithm identity from the basis the catalog
// holds for its OID.
func securityLevels(identity ftypes.CryptoIdentity) (classical, nistCategory *int) {
	basis := algorithms[identity.Value].strengthBasis
	if basis.nistCategory == nil {
		return nil, nil
	}
	if bits, found := basis.classicalStrengths[identity.Parameters]; found {
		classical = new(bits)
	}
	return classical, new(*basis.nistCategory)
}
