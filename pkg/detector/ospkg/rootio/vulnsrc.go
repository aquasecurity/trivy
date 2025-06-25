package rootio

import (
	"maps"
	"slices"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// VulnSrc defines the interface for Root.io vulnerability data source
// The actual implementation will be in trivy-db side: pkg/vulnsrc/rootio/rootio.go
type VulnSrc interface {
	Get(osVer, pkgName string) ([]dbTypes.Advisory, error)
}

// mockVulnSrc is a temporary mock implementation simulating the trivy-db VulnSrc
type mockVulnSrc struct {
	dbc   db.Operation
	inner VulnSrc // This can be replaced with the actual implementation later
}

func newMockVulnSrc(sourceID dbTypes.SourceID) VulnSrc {
	vs := &mockVulnSrc{dbc: db.Config{}}

	switch sourceID {
	case vulnerability.Debian:
		vs.inner = debian.NewVulnSrc()
	case vulnerability.Ubuntu:
		vs.inner = ubuntu.NewVulnSrc()
	case vulnerability.Alpine:
		vs.inner = debian.NewVulnSrc()
	}
	return vs
}

func (v *mockVulnSrc) Get(osVer, pkgName string) ([]dbTypes.Advisory, error) {
	// Get advisories from the original distributors, like Debian or Alpine
	advs, err := v.inner.Get(osVer, pkgName)
	if err != nil {
		return nil, err
	}

	// Simulate the advisories with Root.io's version constraints
	allAdvs := make(map[string]dbTypes.Advisory, len(advs))
	for _, adv := range advs {
		if adv.FixedVersion != "" {
			adv.VulnerableVersions = []string{"<" + adv.FixedVersion}
			adv.PatchedVersions = []string{adv.FixedVersion}
			adv.FixedVersion = "" // Clear fixed version to avoid confusion
		}
		allAdvs[adv.VulnerabilityID] = adv
	}

	advs, err = v.dbc.GetAdvisories(osVer, pkgName)
	if err != nil {
		return nil, err
	}

	rootAdvs := lo.SliceToMap(advs, func(adv dbTypes.Advisory) (string, dbTypes.Advisory) {
		return adv.VulnerabilityID, adv
	})

	// Merge the advisories from the original distributors with Root.io's advisories
	maps.Copy(allAdvs, rootAdvs)

	return slices.Collect(maps.Values(allAdvs)), nil
}
