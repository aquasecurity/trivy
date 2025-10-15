package local

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	FingerprintVersion   = 1
	FingerprintAlgorithm = "sha256"
)

func computeFingerprint(findingID string) types.Fingerprint {
	hash := sha256.Sum256([]byte(findingID))
	return types.Fingerprint{
		Version:   FingerprintVersion,
		Hash:      FingerprintAlgorithm + ":" + hex.EncodeToString(hash[:]),
		FindingID: findingID,
	}
}
