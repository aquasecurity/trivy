package applier

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Applier struct {
	cache cache.Cache

	// cacheMergedLayer is a flag to determine if the merged layer is cached or not.
	// This flag is for tools importing Trivy as a library, not used in Trivy itself.
	cacheMergedLayer bool
}

type Option func(*Applier)

func WithCacheMergedLayer(b bool) Option {
	return func(a *Applier) {
		a.cacheMergedLayer = b
	}
}

func NewApplier(c cache.Cache, opts ...Option) Applier {
	a := &Applier{
		cache:            c,
		cacheMergedLayer: false,
	}
	for _, opt := range opts {
		opt(a)
	}
	return *a
}

func (a Applier) ApplyLayers(imageID string, layerKeys []string) (types.ArtifactDetail, error) {
	var mergedKey string

	// Try to restore the merged layer if the feature is enabled
	if a.cacheMergedLayer {
		var err error
		mergedKey, err = calcMergedKey(layerKeys)
		if err != nil {
			return types.ArtifactDetail{}, xerrors.Errorf("failed to calculate a merged key: %w", err)
		}
		if b, err := a.cache.GetBlob(mergedKey); err == nil {
			return b.ToArtifactDetail(), nil
		}
	}

	var layers []types.BlobInfo
	for _, key := range layerKeys {
		blob, _ := a.cache.GetBlob(key) // nolint
		if blob.SchemaVersion == 0 {
			return types.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", key)
		}
		layers = append(layers, blob)
	}

	mergedLayer := ApplyLayers(layers)
	if mergedLayer.OS == nil {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	imageInfo, _ := a.cache.GetArtifact(imageID) // nolint
	mergedLayer.HistoryPackages = imageInfo.HistoryPackages

	// Store the merged layer if the feature is enabled
	if a.cacheMergedLayer {
		if err := a.cache.PutBlob(mergedKey, mergedLayer.ToBlobInfo()); err != nil {
			log.Logger.Error("Unable to cache the merged layer: %s", err)
		}
	}

	return mergedLayer, nil
}

func calcMergedKey(layerKeys []string) (string, error) {
	if len(layerKeys) == 1 {
		return layerKeys[0], nil
	}

	h := sha256.New()
	if err := json.NewEncoder(h).Encode(layerKeys); err != nil {
		return "", xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	return d.String(), nil
}
