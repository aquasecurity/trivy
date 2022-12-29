package applier

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Applier struct {
	cache cache.LocalArtifactCache
}

func NewApplier(c cache.LocalArtifactCache) Applier {
	return Applier{cache: c}
}

func (a Applier) ApplyLayers(imageID string, layerKeys []string) (types.ArtifactDetail, error) {
	var layers []types.BlobInfo
	for _, key := range layerKeys {
		blob, _ := a.cache.GetBlob(key) // nolint
		if blob.SchemaVersion == 0 {
			return types.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", key)
		}
		layers = append(layers, blob)
	}

	mergedLayer := ApplyLayers(layers)
	if !mergedLayer.OS.Detected() {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	imageInfo, _ := a.cache.GetArtifact(imageID) // nolint
	mergedLayer.HistoryPackages = imageInfo.HistoryPackages

	return mergedLayer, nil
}
