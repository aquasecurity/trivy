package check

import (
	"fmt"
	"slices"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/crypto"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var rules = []rule{
	{
		id:       "CRYPTO-0001",
		title:    "SHA-1 certificate signature",
		severity: dbTypes.SeverityMedium,
		kind:     ftypes.CryptoKindCertificate,
		match:    matchSHA1Signature,
		message:  sha1SignatureMessage,
	},
	{
		id:       "CRYPTO-0002",
		title:    "Small RSA key",
		severity: dbTypes.SeverityHigh,
		kind:     ftypes.CryptoKindKey,
		match:    matchSmallRSAKey,
		message:  smallRSAKeyMessage,
	},
	{
		id:       "CRYPTO-0003",
		title:    "Weak elliptic curve",
		severity: dbTypes.SeverityHigh,
		kind:     ftypes.CryptoKindAlgorithm,
		match:    matchWeakCurve,
		message:  weakCurveMessage,
	},
	{
		id:       "CRYPTO-0004",
		title:    "Expired certificate",
		severity: dbTypes.SeverityMedium,
		kind:     ftypes.CryptoKindCertificate,
		match:    matchExpiredCertificate,
		message:  expiredCertificateMessage,
	},
}

const (
	// oidRSAEncryption identifies the RSA key algorithm, defined by RFC 8017 appendix A.1.
	oidRSAEncryption = "1.2.840.113549.1.1.1"
	// oidECPublicKey identifies the elliptic curve key algorithm, defined by RFC 5480 section 2.1.1.
	oidECPublicKey = "1.2.840.10045.2.1"
)

const (
	// minRSAKeySize is the smallest RSA key size in bits that passes CRYPTO-0002.
	minRSAKeySize = 2048
	// minSecurityLevel is the smallest classical security level in bits that passes CRYPTO-0003.
	minSecurityLevel = 112
)

// sha1SignatureOIDs are the signature algorithms that hash with SHA-1. RSASSA-PSS names its
// hash in parameters that are not collected, so it is left out.
var sha1SignatureOIDs = []string{
	"1.2.840.113549.1.1.5", // sha1WithRSAEncryption, RFC 3279 section 2.2.1
	"1.3.14.3.2.29",        // sha1WithRSAEncryption under the OIW arc
	"1.2.840.10040.4.3",    // dsa-with-sha1, RFC 3279 section 2.2.2
	"1.2.840.10045.4.1",    // ecdsa-with-SHA1, RFC 3279 section 2.2.3
}

func matchSHA1Signature(asset ftypes.CryptoAsset, _ time.Time) (types.CryptoEvidence, bool) {
	signature, found := relatedAlgorithm(asset, ftypes.CryptoRelationshipSignedWith)
	if !found || !slices.Contains(sha1SignatureOIDs, signature.Value) {
		return types.CryptoEvidence{}, false
	}
	return types.CryptoEvidence{
		SignatureAlgorithm:    crypto.AlgorithmName(signature.Value),
		SignatureAlgorithmOID: signature.Value,
	}, true
}

func matchSmallRSAKey(asset ftypes.CryptoAsset, _ time.Time) (types.CryptoEvidence, bool) {
	if asset.Key == nil || asset.Key.Size <= 0 || asset.Key.Size >= minRSAKeySize {
		return types.CryptoEvidence{}, false
	}
	algorithm, found := relatedAlgorithm(asset, ftypes.CryptoRelationshipUsedWith)
	if !found || algorithm.Value != oidRSAEncryption {
		return types.CryptoEvidence{}, false
	}
	return types.CryptoEvidence{
		KeySize: asset.Key.Size,
	}, true
}

func matchWeakCurve(asset ftypes.CryptoAsset, _ time.Time) (types.CryptoEvidence, bool) {
	if asset.Algorithm == nil || asset.Identity.Method != ftypes.CryptoMethodOID ||
		asset.Identity.Value != oidECPublicKey {
		return types.CryptoEvidence{}, false
	}
	level := asset.Algorithm.ClassicalSecurityLevel
	if level == nil || *level >= minSecurityLevel {
		return types.CryptoEvidence{}, false
	}
	// The curve is only evidence, so a parse error is ignored.
	parameters, _ := asset.Identity.AlgorithmParameters()
	return types.CryptoEvidence{
		Curve:                  parameters.Curve,
		ClassicalSecurityLevel: new(*level),
	}, true
}

func matchExpiredCertificate(asset ftypes.CryptoAsset, now time.Time) (types.CryptoEvidence, bool) {
	if asset.Certificate == nil || asset.Certificate.NotAfter.IsZero() ||
		!asset.Certificate.NotAfter.Before(now) {
		return types.CryptoEvidence{}, false
	}
	return types.CryptoEvidence{
		NotAfter: asset.Certificate.NotAfter,
	}, true
}

func sha1SignatureMessage(e types.CryptoEvidence) string {
	return fmt.Sprintf("Certificate is signed with %s", e.SignatureAlgorithm)
}

func smallRSAKeyMessage(e types.CryptoEvidence) string {
	return fmt.Sprintf("RSA key is %d bits, less than %d", e.KeySize, minRSAKeySize)
}

func weakCurveMessage(e types.CryptoEvidence) string {
	curve := "Elliptic curve"
	if e.Curve != "" {
		curve = "Curve " + e.Curve
	}
	level := 0
	if e.ClassicalSecurityLevel != nil {
		level = *e.ClassicalSecurityLevel
	}
	return fmt.Sprintf("%s gives %d bits of security, less than %d", curve, level, minSecurityLevel)
}

func expiredCertificateMessage(e types.CryptoEvidence) string {
	return "Certificate expired on " + e.NotAfter.UTC().Format("2006-01-02")
}

// relatedAlgorithm returns the identity of the algorithm the asset has the given
// relationship with.
func relatedAlgorithm(asset ftypes.CryptoAsset, relationship ftypes.CryptoRelationshipType) (ftypes.CryptoIdentity, bool) {
	for _, r := range asset.Relationships {
		if r.Type == relationship && r.RelatedAsset.Kind == ftypes.CryptoKindAlgorithm &&
			r.RelatedAsset.Identity.Method == ftypes.CryptoMethodOID {
			return r.RelatedAsset.Identity, true
		}
	}
	return ftypes.CryptoIdentity{}, false
}
