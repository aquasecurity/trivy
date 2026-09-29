package types

import (
	"fmt"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
)

// BundleMetadata holds policy bundle metadata.
// This is a lightweight alternative to policy.Metadata to avoid importing
// pkg/policy which has dependencies incompatible with wasip1/wasm.
type BundleMetadata struct {
	Digest       string
	DownloadedAt time.Time
}

func (m BundleMetadata) String() string {
	return fmt.Sprintf(`Check Bundle:
  Digest: %s
  DownloadedAt: %s
`, m.Digest, m.DownloadedAt.UTC())
}

// VersionInfo holds version information for Trivy and its databases.
type VersionInfo struct {
	Version         string             `json:",omitempty"`
	VulnerabilityDB *metadata.Metadata `json:",omitempty"`
	JavaDB          *metadata.Metadata `json:",omitempty"`
	CheckBundle     *BundleMetadata    `json:",omitempty"`
}

func (v VersionInfo) String() string {
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

func formatDBMetadata(title string, meta metadata.Metadata) string {
	return fmt.Sprintf(`%s:
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, title, meta.Version, meta.UpdatedAt.UTC(), meta.NextUpdate.UTC(), meta.DownloadedAt.UTC())
}
