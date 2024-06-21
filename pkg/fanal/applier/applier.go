package applier

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Applier defines operation to scan image layers
type Applier interface {
	ApplyLayers(artifactID string, blobIDs []string) (detail ftypes.ArtifactDetail, err error)
}

type applier struct {
	cache cache.LocalArtifactCache
}

func NewApplier(c cache.LocalArtifactCache) Applier {
	return &applier{cache: c}
}

func (a *applier) ApplyLayers(imageID string, layerKeys []string) (ftypes.ArtifactDetail, error) {
	var layers []ftypes.BlobInfo
	for _, key := range layerKeys {
		blob, _ := a.cache.GetBlob(key) // nolint
		if blob.SchemaVersion == 0 {
			return ftypes.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", key)
		}
		layers = append(layers, blob)
	}

	mergedLayer := ApplyLayers(layers)

	imageInfo, _ := a.cache.GetArtifact(imageID) // nolint
	mergedLayer.ImageConfig = ftypes.ImageConfigDetail{
		Packages:         imageInfo.HistoryPackages,
		Misconfiguration: imageInfo.Misconfiguration,
		Secret:           imageInfo.Secret,
	}

	if !mergedLayer.OS.Detected() {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	return mergedLayer, nil
}
