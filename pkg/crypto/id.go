package crypto

import (
	"strconv"

	"github.com/mitchellh/hashstructure/v2"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// AssignIDs sets the ID of every asset. The ID is derived from the descriptor, the file path
// and the format, so the same material found in different places gets different IDs.
func AssignIDs(assets []ftypes.CryptoAsset) {
	for i := range assets {
		assets[i].AssetID = assetID(assets[i])
	}
}

func assetID(asset ftypes.CryptoAsset) string {
	v := map[string]any{
		"descriptor": asset.Descriptor().String(),
		"filePath":   asset.FilePath,
		"format":     asset.Format,
	}
	hash, err := hashstructure.Hash(v, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
	})
	if err != nil {
		log.Warn("Failed to calculate the cryptographic asset hash",
			log.String("asset", asset.Descriptor().String()), log.FilePath(asset.FilePath), log.Err(err))
	}
	return strconv.FormatUint(hash, 16)
}
