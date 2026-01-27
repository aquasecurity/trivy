package types

import (
	"fmt"
	"time"
)

// DBMetadata holds database metadata for vulnerability or Java DB.
// This is a lightweight struct defined in pkg/types to avoid WASM compatibility
// issues that would arise from importing pkg/db or pkg/policy.
type DBMetadata struct {
	Version      int       `json:",omitempty"`
	UpdatedAt    time.Time `json:",omitempty"`
	NextUpdate   time.Time `json:",omitempty"`
	DownloadedAt time.Time `json:",omitempty"`
}

func (m DBMetadata) String() string {
	return fmt.Sprintf(`  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, m.Version, m.UpdatedAt.UTC(), m.NextUpdate.UTC(), m.DownloadedAt.UTC())
}

// BundleMetadata holds policy/check bundle metadata.
// This is a lightweight alternative to policy.Metadata to avoid importing
// pkg/policy which has dependencies incompatible with wasip1/wasm.
type BundleMetadata struct {
	Digest       string    `json:",omitempty"`
	DownloadedAt time.Time `json:",omitempty"`
}

func (m BundleMetadata) String() string {
	return fmt.Sprintf(`Check Bundle:
  Digest: %s
  DownloadedAt: %s
`, m.Digest, m.DownloadedAt.UTC())
}
