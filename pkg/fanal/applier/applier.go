package applier

import (
	"context"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Applier defines operation to scan image layers
type Applier interface {
	ApplyLayers(ctx context.Context, artifactID string, blobIDs []string) (detail ftypes.ArtifactDetail, err error)
}

type applier struct {
	cache cache.LocalArtifactCache
}

func NewApplier(c cache.LocalArtifactCache) Applier {
	return &applier{cache: c}
}

func (a *applier) ApplyLayers(ctx context.Context, imageID string, layerKeys []string) (ftypes.ArtifactDetail, error) {
	var layers []ftypes.BlobInfo
	var layerInfoList ftypes.Layers
	for _, key := range layerKeys {
		blob, _ := a.cache.GetBlob(ctx, key) // nolint
		if blob.SchemaVersion == 0 {
			return ftypes.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", key)
		}
		if l := blob.Layer(); !lo.IsEmpty(l) {
			layerInfoList = append(layerInfoList, l)
		}
		layers = append(layers, blob)
	}

	mergedLayer := ApplyLayers(layers)

	imageInfo, _ := a.cache.GetArtifact(ctx, imageID) // nolint
	mergedLayer.ImageConfig = ftypes.ImageConfigDetail{
		Packages:         imageInfo.HistoryPackages,
		Misconfiguration: imageInfo.Misconfiguration,
		Secret:           imageInfo.Secret,
	}

	// Fill layers info
	mergedLayer.Layers = layerInfoList

	if !mergedLayer.OS.Detected() {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	return mergedLayer, nil
}
