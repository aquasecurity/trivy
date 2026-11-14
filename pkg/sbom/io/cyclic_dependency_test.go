package io_test

// Regression tests for https://github.com/aquasecurity/trivy/issues/9011
// "Handle no orphan when cyclic dependency"
//
// Real-world case (discussion #9006): Amazon Linux rpm packages git and
// perl-Git depend on each other. On encode, each has a parent, so neither is
// linked to the parent (OS) component: the pair forms an island detached from
// the root. On decode of such an SBOM, the cycle members are unreachable by
// dependency traversal and fall into the orphan bucket.

import (
	"context"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

func reproCycleReport() types.Report {
	return types.Report{
		SchemaVersion: 2,
		ArtifactName:  "amazonlinux:2023",
		ArtifactType:  ftypes.TypeContainerImage,
		Metadata: types.Metadata{
			OS: &ftypes.OS{
				Family: ftypes.Amazon,
				Name:   "2023",
			},
		},
		Results: []types.Result{
			{
				Target: "amazonlinux:2023 (amazon 2023)",
				Type:   ftypes.Amazon,
				Class:  types.ClassOSPkg,
				Packages: []ftypes.Package{
					{
						ID:      "bash@5.2.15-1.amzn2023.0.2",
						Name:    "bash",
						Version: "5.2.15-1.amzn2023.0.2",
						Identifier: ftypes.PkgIdentifier{
							UID: "AAAAAAAAAAAAAAAA",
							PURL: &packageurl.PackageURL{
								Type:    packageurl.TypeRPM,
								Name:    "bash",
								Version: "5.2.15-1.amzn2023.0.2",
							},
						},
					},
					{
						ID:      "git@2.47.1-1.amzn2023.0.2",
						Name:    "git",
						Version: "2.47.1-1.amzn2023.0.2",
						Identifier: ftypes.PkgIdentifier{
							UID: "BBBBBBBBBBBBBBBB",
							PURL: &packageurl.PackageURL{
								Type:    packageurl.TypeRPM,
								Name:    "git",
								Version: "2.47.1-1.amzn2023.0.2",
							},
						},
						DependsOn: []string{"perl-Git@2.47.1-1.amzn2023.0.2"},
					},
					{
						ID:      "perl-Git@2.47.1-1.amzn2023.0.2",
						Name:    "perl-Git",
						Version: "2.47.1-1.amzn2023.0.2",
						Identifier: ftypes.PkgIdentifier{
							UID: "CCCCCCCCCCCCCCCC",
							PURL: &packageurl.PackageURL{
								Type:    packageurl.TypeRPM,
								Name:    "perl-Git",
								Version: "2.47.1-1.amzn2023.0.2",
							},
						},
						DependsOn: []string{"git@2.47.1-1.amzn2023.0.2"},
					},
				},
			},
		},
	}
}

// reachableFrom returns the set of component UUIDs reachable from `start`
// through the BOM relationship graph.
func reachableFrom(bom *core.BOM, start uuid.UUID) map[uuid.UUID]struct{} {
	visited := make(map[uuid.UUID]struct{})
	queue := []uuid.UUID{start}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if _, ok := visited[id]; ok {
			continue
		}
		visited[id] = struct{}{}
		for _, rel := range bom.Relationships()[id] {
			queue = append(queue, rel.Dependency)
		}
	}
	return visited
}

func TestEncoder_Encode_CyclicDependencies(t *testing.T) {
	report := reproCycleReport()

	// Step 1: encode the report (e.g. `trivy image -f cyclonedx`)
	bom, err := sbomio.NewEncoder().Encode(report)
	require.NoError(t, err)

	root := bom.Root()
	require.NotNil(t, root)

	// Every package component must be reachable from the root component.
	// A closed dependency cycle currently forms an island detached from root:
	// each member has a parent inside the cycle, so no member is linked to the
	// parent (OS) component.
	reachable := reachableFrom(bom, root.ID())
	for id, c := range bom.Components() {
		if c.Root {
			continue
		}
		assert.Contains(t, reachable, id, "component %s is detached from the root component", c.Name)
	}

	// Step 2: decode the produced BOM (e.g. `trivy sbom scan.cdx.json`).
	// Cycle members unreachable from the OS component currently fall into the
	// orphan bucket.
	var sbom types.SBOM
	err = sbomio.NewDecoder(bom).Decode(context.Background(), &sbom)
	require.NoError(t, err)
	require.NotEmpty(t, sbom.Packages)

	got := make(map[string]string) // name -> package
	for _, info := range sbom.Packages {
		for _, pkg := range info.Packages {
			got[pkg.Name] = pkg.ID
		}
	}
	assert.Contains(t, got, "bash")
	assert.Contains(t, got, "git", "git is lost or orphaned during decode")
	assert.Contains(t, got, "perl-Git", "perl-Git is lost or orphaned during decode")
}
