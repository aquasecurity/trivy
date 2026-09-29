package version

import (
	"context"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	javadb "github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

// VersionOption is a functional option for NewVersionInfo
type VersionOption func(*versionOptions)

type versionOptions struct {
	forServer bool
}

// Server returns a VersionOption that excludes JavaDB and CheckBundle
// from version info, as these are managed on the client side in client/server mode.
func Server() VersionOption {
	return func(o *versionOptions) {
		o.forServer = true
	}
}

func NewVersionInfo(cacheDir string, opts ...VersionOption) types.VersionInfo {
	var options versionOptions
	for _, opt := range opts {
		opt(&options)
	}

	var dbMeta *metadata.Metadata
	var javadbMeta *metadata.Metadata
	var pbMeta *types.BundleMetadata

	mc := metadata.NewClient(db.Dir(cacheDir))
	meta, err := mc.Get()
	if err != nil {
		log.Debug("Failed to get DB metadata", log.Err(err))
	}
	if !meta.UpdatedAt.IsZero() && !meta.NextUpdate.IsZero() && meta.Version != 0 {
		dbMeta = &metadata.Metadata{
			Version:      meta.Version,
			NextUpdate:   meta.NextUpdate.UTC(),
			UpdatedAt:    meta.UpdatedAt.UTC(),
			DownloadedAt: meta.DownloadedAt.UTC(),
		}
	}

	// Skip JavaDB and CheckBundle for server mode as they are managed on the client side
	if !options.forServer {
		mcJava := javadb.NewMetadata(filepath.Join(cacheDir, "java-db"))
		metaJava, err := mcJava.Get()
		if err != nil {
			log.Debug("Failed to get Java DB metadata", log.Err(err))
		}
		if !metaJava.UpdatedAt.IsZero() && !metaJava.NextUpdate.IsZero() && metaJava.Version != 0 {
			javadbMeta = &metadata.Metadata{
				Version:      metaJava.Version,
				NextUpdate:   metaJava.NextUpdate.UTC(),
				UpdatedAt:    metaJava.UpdatedAt.UTC(),
				DownloadedAt: metaJava.DownloadedAt.UTC(),
			}
		}

		pc, err := policy.NewClient(cacheDir, false, "")
		if err != nil {
			log.Debug("Failed to instantiate policy client", log.Err(err))
		}
		if pc != nil && err == nil {
			ctx := log.WithContextPrefix(context.TODO(), log.PrefixMisconfiguration)
			pbMetaRaw, err := pc.GetMetadata(ctx)

			if err != nil {
				log.Debug("Failed to get policy metadata", log.Err(err))
			} else {
				pbMeta = &types.BundleMetadata{
					Digest:       pbMetaRaw.Digest,
					DownloadedAt: pbMetaRaw.DownloadedAt.UTC(),
				}
			}
		}
	}

	return types.VersionInfo{
		Version:         app.Version(),
		VulnerabilityDB: dbMeta,
		JavaDB:          javadbMeta,
		CheckBundle:     pbMeta,
	}
}
