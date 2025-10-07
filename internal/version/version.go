package version

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	javadb "github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

type VersionInfo struct {
	Version         string             `json:",omitempty"`
	VulnerabilityDB *metadata.Metadata `json:",omitempty"`
	JavaDB          *metadata.Metadata `json:",omitempty"`
	CheckBundle     *policy.Metadata   `json:",omitempty"`
}

func formatDBMetadata(title string, meta metadata.Metadata) string {
	return fmt.Sprintf(`%s:
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, title, meta.Version, meta.UpdatedAt.UTC(), meta.NextUpdate.UTC(), meta.DownloadedAt.UTC())
}

func (v *VersionInfo) String() string {
	output := fmt.Sprintf("Version: %s\n", v.Version)
	if v.VulnerabilityDB != nil {
		output += formatDBMetadata("Vulnerability DB", *v.VulnerabilityDB)
	}
	if v.JavaDB != nil {
		output += formatDBMetadata("Java DB", *v.JavaDB)
	}
	if v.CheckBundle != nil {
		output += v.CheckBundle.String()
	}
	return output
}

func NewVersionInfo(cacheDir string) VersionInfo {
	var dbMeta *metadata.Metadata
	var javadbMeta *metadata.Metadata

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

	var pbMeta *policy.Metadata
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
			pbMeta = &policy.Metadata{
				Digest:       pbMetaRaw.Digest,
				DownloadedAt: pbMetaRaw.DownloadedAt.UTC(),
			}
		}
	}

	return VersionInfo{
		Version:         app.Version(),
		VulnerabilityDB: dbMeta,
		JavaDB:          javadbMeta,
		CheckBundle:     pbMeta,
	}
}
