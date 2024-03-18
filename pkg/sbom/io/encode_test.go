package io_test

import (
	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncoder_Encode(t *testing.T) {
	tests := []struct {
		name           string
		report         types.Report
		wantComponents map[uuid.UUID]*core.Component
		wantRels       map[uuid.UUID][]core.Relationship
		wantVulns      map[uuid.UUID][]core.Vulnerability
		wantErr        string
	}{
		{
			name: "container image",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "debian:12",
				ArtifactType:  ftypes.ArtifactContainerImage,
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: ftypes.Debian,
						Name:   "12",
					},
					RepoTags: []string{
						"debian:latest",
						"debian:12",
					},
					RepoDigests: []string{
						"debian@sha256:4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90",
					},
				},
				Results: []types.Result{
					{
						Target: "debian:12",
						Type:   ftypes.Debian,
						Class:  types.ClassOSPkg,
						Packages: []ftypes.Package{
							{
								ID:      "libc6@2.37-15.1",
								Name:    "libc6",
								Version: "2.37-15.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeDebian,
										Name:    "libc6",
										Version: "2.37-15.1",
									},
								},
							},
							{
								ID:      "curl@7.50.3-1",
								Name:    "curl",
								Version: "7.50.3-1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeDebian,
										Name:    "curl",
										Version: "7.50.3-1",
									},
								},
								DependsOn: []string{
									"libc6@2.37-15.1",
								},
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgName:          "curl",
								PkgID:            "curl@7.50.3-1",
								VulnerabilityID:  "CVE-2021-22876",
								InstalledVersion: "7.50.3-1",
								FixedVersion:     "7.50.3-1+deb9u1",
								Vulnerability: dtypes.Vulnerability{
									Severity: "HIGH",
								},
							},
						},
					},
					{
						Target: "Java",
						Type:   ftypes.Jar,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:       "org.apache.xmlgraphics/batik-anim:1.9.1",
								Name:     "org.apache.xmlgraphics/batik-anim",
								Version:  "1.9.1",
								FilePath: "/app/batik-anim-1.9.1.jar",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.xmlgraphics",
										Name:      "batik-anim",
										Version:   "1.9.1",
									},
								},
							},
						},
					},
				},
			},
			wantComponents: map[uuid.UUID]*core.Component{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					Type: core.TypeContainerImage,
					Name: "debian:12",
					Root: true,
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    packageurl.TypeOCI,
							Name:    "debian",
							Version: "sha256:4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90",
							Qualifiers: packageurl.Qualifiers{
								{
									Key:   "repository_url",
									Value: "index.docker.io/library/debian",
								},
							},
						},
						BOMRef: "pkg:oci/debian@sha256%3A4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90?repository_url=index.docker.io%2Flibrary%2Fdebian",
					},
					Properties: []core.Property{
						{
							Name:  core.PropertyRepoDigest,
							Value: "debian@sha256:4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90",
						},
						{
							Name:  core.PropertyRepoTag,
							Value: "debian:12",
						},
						{
							Name:  core.PropertyRepoTag,
							Value: "debian:latest",
						},
						{
							Name:  core.PropertySchemaVersion,
							Value: "2",
						},
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
					Type:    core.TypeOS,
					Name:    "debian",
					Version: "12",
					Properties: []core.Property{
						{
							Name:  core.PropertyClass,
							Value: "os-pkgs",
						},
						{
							Name:  core.PropertyType,
							Value: "debian",
						},
					},
					PkgID: core.PkgID{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"): {
					Type:    core.TypeLibrary,
					Name:    "libc6",
					Version: "2.37-15.1",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "libc6@2.37-15.1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "debian",
						},
					},
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    packageurl.TypeDebian,
							Name:    "libc6",
							Version: "2.37-15.1",
						},
						BOMRef: "pkg:deb/libc6@2.37-15.1",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					Type:    core.TypeLibrary,
					Name:    "curl",
					Version: "7.50.3-1",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "curl@7.50.3-1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "debian",
						},
					},
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    packageurl.TypeDebian,
							Name:    "curl",
							Version: "7.50.3-1",
						},
						BOMRef: "pkg:deb/curl@7.50.3-1",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): {
					Type:    core.TypeLibrary,
					Group:   "org.apache.xmlgraphics",
					Name:    "batik-anim",
					Version: "1.9.1",
					Files: []core.File{
						{
							Path: "/app/batik-anim-1.9.1.jar",
						},
					},
					Properties: []core.Property{
						{
							Name:  core.PropertyFilePath,
							Value: "/app/batik-anim-1.9.1.jar",
						},
						{
							Name:  core.PropertyPkgID,
							Value: "org.apache.xmlgraphics/batik-anim:1.9.1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "jar",
						},
					},
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "org.apache.xmlgraphics",
							Name:      "batik-anim",
							Version:   "1.9.1",
						},
						BOMRef: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1",
					},
				},
			},
			wantRels: map[uuid.UUID][]core.Relationship{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"),
						Type:       core.RelationshipContains,
					},
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"),
						Type:       core.RelationshipContains,
					},
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"): nil,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): nil,
			},
			wantVulns: map[uuid.UUID][]core.Vulnerability{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					{
						ID:               "CVE-2021-22876",
						PkgID:            "curl@7.50.3-1",
						PkgName:          "curl",
						InstalledVersion: "7.50.3-1",
						FixedVersion:     "7.50.3-1+deb9u1",
						Vulnerability: dtypes.Vulnerability{
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name: "invalid digest",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "debian:12",
				ArtifactType:  ftypes.ArtifactContainerImage,
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: ftypes.Debian,
						Name:   "12",
					},
					RepoTags: []string{
						"debian:12",
					},
					RepoDigests: []string{
						"debian@sha256:123",
					},
				},
			},
			wantErr: "failed to parse digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			opts := core.Options{GenerateBOMRef: true}
			got, err := sbomio.NewEncoder(opts).Encode(tt.report)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			require.Len(t, got.Components(), len(tt.wantComponents))
			for id, want := range tt.wantComponents {
				assert.EqualExportedValues(t, *want, *got.Components()[id])
			}

			assert.Equal(t, tt.wantRels, got.Relationships())
			assert.Equal(t, tt.wantVulns, got.Vulnerabilities())
		})
	}
}
