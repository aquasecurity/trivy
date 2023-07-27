package version

import (
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/stretchr/testify/assert"
)

func Test_BuildVersionInfo(t *testing.T) {

	expected := VersionInfo{
		Version: "dev",
		VulnerabilityDB: &metadata.Metadata{
			Version:      2,
			NextUpdate:   time.Date(2023, 7, 20, 18, 11, 37, 696263532, time.UTC),
			UpdatedAt:    time.Date(2023, 7, 20, 12, 11, 37, 696263932, time.UTC),
			DownloadedAt: time.Date(2023, 7, 25, 7, 1, 41, 239158000, time.UTC),
		},
		JavaDB: &metadata.Metadata{
			Version:      1,
			NextUpdate:   time.Date(2023, 7, 28, 1, 3, 52, 169192565, time.UTC),
			UpdatedAt:    time.Date(2023, 7, 25, 1, 3, 52, 169192765, time.UTC),
			DownloadedAt: time.Date(2023, 7, 25, 9, 37, 48, 906152000, time.UTC),
		},
		PolicyBundle: &policy.Metadata{
			Digest:       "sha256:829832357626da2677955e3b427191212978ba20012b6eaa03229ca28569ae43",
			DownloadedAt: time.Date(2023, 7, 23, 16, 40, 33, 122462000, time.UTC),
		},
	}
	assert.Equal(t, expected, NewVersionInfo("testdata/testcache"))
}

func Test_VersionInfoString(t *testing.T) {
	expected := `Version: dev
Vulnerability DB:
  Version: 2
  UpdatedAt: 2023-07-20 12:11:37.696263932 +0000 UTC
  NextUpdate: 2023-07-20 18:11:37.696263532 +0000 UTC
  DownloadedAt: 2023-07-25 07:01:41.239158 +0000 UTC
Java DB:
  Version: 1
  UpdatedAt: 2023-07-25 01:03:52.169192765 +0000 UTC
  NextUpdate: 2023-07-28 01:03:52.169192565 +0000 UTC
  DownloadedAt: 2023-07-25 09:37:48.906152 +0000 UTC
Policy Bundle:
  Digest: sha256:829832357626da2677955e3b427191212978ba20012b6eaa03229ca28569ae43
  DownloadedAt: 2023-07-23 16:40:33.122462 +0000 UTC
`
	versionInfo := NewVersionInfo("testdata/testcache")
	assert.Equal(t, expected, versionInfo.String())
}
