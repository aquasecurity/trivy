package io_test

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
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
				ArtifactType:  artifact.TypeContainerImage,
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
					ImageConfig: v1.ConfigFile{
						Config: v1.Config{
							Labels: map[string]string{
								"vendor": "aquasecurity",
							},
						},
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
									UID: "33654D2C483FC3AD",
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
									UID: "51BA9E006222819D",
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
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "51BA9E006222819D",
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
								ID:       "com.fasterxml.jackson.core:jackson-databind:2.13.4",
								Name:     "com.fasterxml.jackson.core:jackson-databind",
								Version:  "2.13.4",
								FilePath: "/foo/jackson-databind-2.13.4.jar",
								Identifier: ftypes.PkgIdentifier{
									UID: "A6BD5A2FE5C00E10",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.fasterxml.jackson.core",
										Name:      "jackson-databind",
										Version:   "2.13.4",
									},
								},
							},
							{
								ID:       "com.fasterxml.jackson.core:jackson-databind:2.13.4",
								Name:     "com.fasterxml.jackson.core:jackson-databind",
								Version:  "2.13.4",
								FilePath: "/bar/jackson-databind-2.13.4.jar",
								Identifier: ftypes.PkgIdentifier{
									UID: "64244651208EC759",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.fasterxml.jackson.core",
										Name:      "jackson-databind",
										Version:   "2.13.4",
									},
								},
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgName:          "com.fasterxml.jackson.core:jackson-databind",
								PkgID:            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
								VulnerabilityID:  "CVE-2022-42003",
								InstalledVersion: "2.13.4",
								FixedVersion:     "2.12.7.1, 2.13.4.2",
								PkgPath:          "/foo/jackson-databind-2.13.4.jar",
								Vulnerability: dtypes.Vulnerability{
									Severity: "HIGH",
								},
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "A6BD5A2FE5C00E10",
								},
							},
							{
								PkgName:          "com.fasterxml.jackson.core:jackson-databind",
								PkgID:            "com.fasterxml.jackson.core:jackson-databind:2.13.4",
								VulnerabilityID:  "CVE-2022-42003",
								InstalledVersion: "2.13.4",
								FixedVersion:     "2.12.7.1, 2.13.4.2",
								PkgPath:          "/bar/jackson-databind-2.13.4.jar",
								Vulnerability: dtypes.Vulnerability{
									Severity: "HIGH",
								},
								PkgIdentifier: ftypes.PkgIdentifier{
									UID: "64244651208EC759",
								},
							},
						},
					},
					{
						Target: "trivy",
						Type:   ftypes.GoBinary,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:      "github.com/aquasecurity/trivy@v0.57.1",
								Name:    "github.com/aquasecurity/trivy",
								Version: "v0.57.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "106fee7e57f0b952",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/aquasecurity",
										Name:      "trivy",
										Version:   "v0.57.1",
									},
								},
								Relationship: ftypes.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
									"stdlib@v1.22.9",
								},
							},
							{
								ID:      "stdlib@v1.22.9",
								Name:    "stdlib",
								Version: "v1.22.9",
								Identifier: ftypes.PkgIdentifier{
									UID: "62e7c8aaebd94b1e",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGolang,
										Name:    "stdlib",
										Version: "v1.22.9",
									},
								},
								Relationship: ftypes.RelationshipDirect,
							},
							{
								ID:      "github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
								Name:    "github.com/aquasecurity/go-version",
								Version: "v0.0.0-20240603093900-cf8a8d29271d",
								Identifier: ftypes.PkgIdentifier{
									UID: "350aed171d8ebed5",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/aquasecurity",
										Name:      "go-version",
										Version:   "v0.0.0-20240603093900-cf8a8d29271d",
									},
								},
								Relationship: ftypes.RelationshipUnknown,
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
					PkgIdentifier: ftypes.PkgIdentifier{
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
							Name:  "Labels:vendor",
							Value: "aquasecurity",
						},
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
					PkgIdentifier: ftypes.PkgIdentifier{
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
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "33654D2C483FC3AD",
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
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "51BA9E006222819D",
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
					Group:   "com.fasterxml.jackson.core",
					Name:    "jackson-databind",
					Version: "2.13.4",
					Files: []core.File{
						{
							Path: "/foo/jackson-databind-2.13.4.jar",
						},
					},
					Properties: []core.Property{
						{
							Name:  core.PropertyFilePath,
							Value: "/foo/jackson-databind-2.13.4.jar",
						},
						{
							Name:  core.PropertyPkgID,
							Value: "com.fasterxml.jackson.core:jackson-databind:2.13.4",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "jar",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "A6BD5A2FE5C00E10",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.fasterxml.jackson.core",
							Name:      "jackson-databind",
							Version:   "2.13.4",
						},
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): {
					Type:    core.TypeLibrary,
					Group:   "com.fasterxml.jackson.core",
					Name:    "jackson-databind",
					Version: "2.13.4",
					Files: []core.File{
						{
							Path: "/bar/jackson-databind-2.13.4.jar",
						},
					},
					Properties: []core.Property{
						{
							Name:  core.PropertyFilePath,
							Value: "/bar/jackson-databind-2.13.4.jar",
						},
						{
							Name:  core.PropertyPkgID,
							Value: "com.fasterxml.jackson.core:jackson-databind:2.13.4",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "jar",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "64244651208EC759",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.fasterxml.jackson.core",
							Name:      "jackson-databind",
							Version:   "2.13.4",
						},
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000006",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000007"): {
					Type: core.TypeApplication,
					Name: "trivy",
					Properties: []core.Property{
						{
							Name:  core.PropertyClass,
							Value: "lang-pkgs",
						},
						{
							Name:  core.PropertyType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000007",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000008"): {
					Type:    core.TypeLibrary,
					Name:    "github.com/aquasecurity/trivy",
					Version: "v0.57.1",
					SrcFile: "trivy",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "github.com/aquasecurity/trivy@v0.57.1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "106fee7e57f0b952",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeGolang,
							Namespace: "github.com/aquasecurity",
							Name:      "trivy",
							Version:   "v0.57.1",
						},
						BOMRef: "pkg:golang/github.com/aquasecurity/trivy@v0.57.1",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000009"): {
					Type:    core.TypeLibrary,
					Name:    "stdlib",
					Version: "v1.22.9",
					SrcFile: "trivy",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "stdlib@v1.22.9",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "62e7c8aaebd94b1e",
						PURL: &packageurl.PackageURL{
							Type:    packageurl.TypeGolang,
							Name:    "stdlib",
							Version: "v1.22.9",
						},
						BOMRef: "pkg:golang/stdlib@v1.22.9",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000010"): {
					Type:    core.TypeLibrary,
					Name:    "github.com/aquasecurity/go-version",
					Version: "v0.0.0-20240603093900-cf8a8d29271d",
					SrcFile: "trivy",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "350aed171d8ebed5",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeGolang,
							Namespace: "github.com/aquasecurity",
							Name:      "go-version",
							Version:   "v0.0.0-20240603093900-cf8a8d29271d",
						},
						BOMRef: "pkg:golang/github.com/aquasecurity/go-version@v0.0.0-20240603093900-cf8a8d29271d",
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
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"),
						Type:       core.RelationshipContains,
					},
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000007"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
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
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): nil,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000007"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000008"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000008"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000010"),
						Type:       core.RelationshipDependsOn,
					},
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000009"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000009"): nil,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000010"): nil,
			},
			wantVulns: map[uuid.UUID][]core.Vulnerability{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					{
						ID:               "CVE-2021-22876",
						PkgName:          "curl",
						InstalledVersion: "7.50.3-1",
						FixedVersion:     "7.50.3-1+deb9u1",
						Vulnerability: dtypes.Vulnerability{
							Severity: "HIGH",
						},
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): {
					{
						ID:               "CVE-2022-42003",
						PkgName:          "com.fasterxml.jackson.core:jackson-databind",
						InstalledVersion: "2.13.4",
						FixedVersion:     "2.12.7.1, 2.13.4.2",
						Vulnerability: dtypes.Vulnerability{
							Severity: "HIGH",
						},
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): {
					{
						ID:               "CVE-2022-42003",
						PkgName:          "com.fasterxml.jackson.core:jackson-databind",
						InstalledVersion: "2.13.4",
						FixedVersion:     "2.12.7.1, 2.13.4.2",
						Vulnerability: dtypes.Vulnerability{
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name: "root package",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "gobinary",
				ArtifactType:  artifact.TypeFilesystem,
				Results: []types.Result{
					{
						Target: "test",
						Type:   ftypes.GoBinary,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:   "github.com/org/root",
								Name: "github.com/org/root",
								Identifier: ftypes.PkgIdentifier{
									UID: "03D528806D964D22",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/org",
										Name:      "root",
									},
								},
								Relationship: ftypes.RelationshipRoot,
								DependsOn: []string{
									"github.com/org/direct@v1.0.0",
									"stdlib@v1.22.1",
								},
							},
							{
								ID:      "github.com/org/direct@v1.0.0",
								Name:    "github.com/org/direct",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "A74CADAD4D9805FF",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/org",
										Name:      "direct",
										Version:   "v1.0.0",
									},
								},
								Relationship: ftypes.RelationshipDirect,
								DependsOn: []string{
									"github.com/org/indirect@v2.0.0",
								},
							},
							{
								ID:      "github.com/org/indirect@v2.0.0",
								Name:    "github.com/org/indirect",
								Version: "v2.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "955AB4E7E24AC085",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/org",
										Name:      "indirect",
										Version:   "v2.0.0",
									},
								},
								Relationship: ftypes.RelationshipIndirect,
							},
							{
								ID:      "stdlib@v1.22.1",
								Name:    "stdlib",
								Version: "v1.22.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "49728B9674E318A6",
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGolang,
										Name:    "stdlib",
										Version: "v1.22.1",
									},
								},
								Relationship: ftypes.RelationshipDirect,
							},
						},
					},
				},
			},
			wantComponents: map[uuid.UUID]*core.Component{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					Type: core.TypeFilesystem,
					Name: "gobinary",
					Root: true,
					Properties: []core.Property{
						{
							Name:  core.PropertySchemaVersion,
							Value: "2",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
					Type: core.TypeApplication,
					Name: "test",
					Properties: []core.Property{
						{
							Name:  core.PropertyClass,
							Value: "lang-pkgs",
						},
						{
							Name:  core.PropertyType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"): {
					Type:    core.TypeLibrary,
					Name:    "github.com/org/root",
					SrcFile: "test",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "github.com/org/root",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "03D528806D964D22",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeGolang,
							Namespace: "github.com/org",
							Name:      "root",
						},
						BOMRef: "pkg:golang/github.com/org/root",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					Type:    core.TypeLibrary,
					Name:    "github.com/org/direct",
					Version: "v1.0.0",
					SrcFile: "test",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "github.com/org/direct@v1.0.0",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "A74CADAD4D9805FF",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeGolang,
							Namespace: "github.com/org",
							Name:      "direct",
							Version:   "v1.0.0",
						},
						BOMRef: "pkg:golang/github.com/org/direct@v1.0.0",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): {
					Type:    core.TypeLibrary,
					Name:    "github.com/org/indirect",
					Version: "v2.0.0",
					SrcFile: "test",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "github.com/org/indirect@v2.0.0",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "955AB4E7E24AC085",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeGolang,
							Namespace: "github.com/org",
							Name:      "indirect",
							Version:   "v2.0.0",
						},
						BOMRef: "pkg:golang/github.com/org/indirect@v2.0.0",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): {
					Type:    core.TypeLibrary,
					Name:    "stdlib",
					Version: "v1.22.1",
					SrcFile: "test",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "stdlib@v1.22.1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "gobinary",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "49728B9674E318A6",
						PURL: &packageurl.PackageURL{
							Type:    packageurl.TypeGolang,
							Name:    "stdlib",
							Version: "v1.22.1",
						},
						BOMRef: "pkg:golang/stdlib@v1.22.1",
					},
				},
			},
			wantRels: map[uuid.UUID][]core.Relationship{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"),
						Type:       core.RelationshipDependsOn,
					},
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): nil,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): nil,
			},
			wantVulns: make(map[uuid.UUID][]core.Vulnerability),
		},
		{
			name: "SBOM file",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "report.cdx.json",
				ArtifactType:  artifact.TypeCycloneDX,
				Results: []types.Result{
					{
						Target: "Java",
						Type:   ftypes.Jar,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:      "org.apache.logging.log4j:log4j-core:2.23.1",
								Name:    "org.apache.logging.log4j:log4j-core",
								Version: "2.23.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "6C0AE96901617503",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.logging.log4j",
										Name:      "log4j-core",
										Version:   "2.23.1",
									},
								},
								FilePath: "log4j-core-2.23.1.jar",
							},
						},
					},
				},
				BOM: newTestBOM(t),
			},
			wantComponents: map[uuid.UUID]*core.Component{
				uuid.MustParse("2ff14136-e09f-4df9-80ea-000000000001"): appComponent,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): libComponent,
			},
			wantRels: map[uuid.UUID][]core.Relationship{
				uuid.MustParse("2ff14136-e09f-4df9-80ea-000000000001"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): nil,
			},
			wantVulns: make(map[uuid.UUID][]core.Vulnerability),
		},
		{
			name: "SBOM file without root component",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "report.cdx.json",
				ArtifactType:  artifact.TypeCycloneDX,
				Results: []types.Result{
					{
						Target: "Java",
						Type:   ftypes.Jar,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:      "org.apache.logging.log4j:log4j-core:2.23.1",
								Name:    "org.apache.logging.log4j:log4j-core",
								Version: "2.23.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "6C0AE96901617503",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.logging.log4j",
										Name:      "log4j-core",
										Version:   "2.23.1",
									},
								},
								FilePath: "log4j-core-2.23.1.jar",
							},
						},
					},
				},
				BOM: newTestBOM2(t),
			},
			wantComponents: map[uuid.UUID]*core.Component{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): fsComponent,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): libComponent,
			},
			wantRels: map[uuid.UUID][]core.Relationship{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): nil,
			},
			wantVulns: make(map[uuid.UUID][]core.Vulnerability),
		},
		{
			name: "multimodule maven project",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "pom.xml",
				ArtifactType:  artifact.TypeFilesystem,
				Results: []types.Result{
					{
						Target: "pom.xml",
						Type:   ftypes.Pom,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:      "com.example:root:1.0.0",
								Name:    "com.example:root",
								Version: "1.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "f684ec661900abbf",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.example",
										Name:      "root",
										Version:   "1.0.0",
									},
								},
								Relationship: ftypes.RelationshipRoot,
								DependsOn: []string{
									"com.example:module1:1.0.0",
									"com.example:module2:2.0.0",
								},
							},
							{
								ID:      "com.example:module1:1.0.0",
								Name:    "com.example:module1",
								Version: "1.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "ce0d29336874c431",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.example",
										Name:      "module1",
										Version:   "1.0.0",
									},
								},
								Relationship: ftypes.RelationshipWorkspace,
								DependsOn: []string{
									"org.example:example-api:1.1.1",
								},
							},
							{
								ID:      "com.example:module2:2.0.0",
								Name:    "com.example:module2",
								Version: "2.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "387238ffef6dfa9d",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.example",
										Name:      "module2",
										Version:   "2.0.0",
									},
								},
								Relationship: ftypes.RelationshipWorkspace,
								DependsOn: []string{
									"org.example:example-dependency:1.2.3",
								},
							},
							{
								ID:      "org.example:example-api:1.1.1",
								Name:    "org.example:example-api",
								Version: "1.1.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "45cdc62618708bb7",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.example",
										Name:      "example-api",
										Version:   "1.1.1",
									},
								},
								Relationship: ftypes.RelationshipDirect,
							},
							{
								ID:      "org.example:example-dependency:1.2.3",
								Name:    "org.example:example-dependency",
								Version: "1.2.3",
								Identifier: ftypes.PkgIdentifier{
									UID: "52fbe353a46651",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.example",
										Name:      "example-dependency",
										Version:   "1.2.3",
									},
								},
								Relationship: ftypes.RelationshipDirect,
								DependsOn: []string{
									"org.example:example-api:2.0.0",
								},
							},
							{
								ID:      "org.example:example-api:2.0.0",
								Name:    "org.example:example-api",
								Version: "2.0.0",
								Identifier: ftypes.PkgIdentifier{
									UID: "f71d14b6d2bd8810",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.example",
										Name:      "example-api",
										Version:   "2.0.0",
									},
								},
								Relationship: ftypes.RelationshipIndirect,
							},
						},
					},
				},
			},
			wantComponents: map[uuid.UUID]*core.Component{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					Type: core.TypeFilesystem,
					Name: "pom.xml",
					Root: true,
					Properties: []core.Property{
						{
							Name:  core.PropertySchemaVersion,
							Value: "2",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
					Type: core.TypeApplication,
					Name: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyClass,
							Value: "lang-pkgs",
						},
						{
							Name:  core.PropertyType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"): {
					Type:    core.TypeLibrary,
					Group:   "com.example",
					Name:    "root",
					Version: "1.0.0",
					SrcFile: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "com.example:root:1.0.0",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "f684ec661900abbf",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.example",
							Name:      "root",
							Version:   "1.0.0",
						},
						BOMRef: "pkg:maven/com.example/root@1.0.0",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					Type:    core.TypeLibrary,
					Group:   "com.example",
					Name:    "module1",
					Version: "1.0.0",
					SrcFile: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "com.example:module1:1.0.0",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "ce0d29336874c431",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.example",
							Name:      "module1",
							Version:   "1.0.0",
						},
						BOMRef: "pkg:maven/com.example/module1@1.0.0",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): {
					Type:    core.TypeLibrary,
					Group:   "com.example",
					Name:    "module2",
					Version: "2.0.0",
					SrcFile: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "com.example:module2:2.0.0",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "387238ffef6dfa9d",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.example",
							Name:      "module2",
							Version:   "2.0.0",
						},
						BOMRef: "pkg:maven/com.example/module2@2.0.0",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): {
					Type:    core.TypeLibrary,
					Group:   "org.example",
					Name:    "example-api",
					Version: "1.1.1",
					SrcFile: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "org.example:example-api:1.1.1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "45cdc62618708bb7",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "org.example",
							Name:      "example-api",
							Version:   "1.1.1",
						},
						BOMRef: "pkg:maven/org.example/example-api@1.1.1",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000007"): {
					Type:    core.TypeLibrary,
					Group:   "org.example",
					Name:    "example-dependency",
					Version: "1.2.3",
					SrcFile: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "org.example:example-dependency:1.2.3",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "52fbe353a46651",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "org.example",
							Name:      "example-dependency",
							Version:   "1.2.3",
						},
						BOMRef: "pkg:maven/org.example/example-dependency@1.2.3",
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000008"): {
					Type:    core.TypeLibrary,
					Group:   "org.example",
					Name:    "example-api",
					Version: "2.0.0",
					SrcFile: "pom.xml",
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "org.example:example-api:2.0.0",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "pom",
						},
					},
					PkgIdentifier: ftypes.PkgIdentifier{
						UID: "f71d14b6d2bd8810",
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "org.example",
							Name:      "example-api",
							Version:   "2.0.0",
						},
						BOMRef: "pkg:maven/org.example/example-api@2.0.0",
					},
				},
			},
			wantRels: map[uuid.UUID][]core.Relationship{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000003"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"),
						Type:       core.RelationshipDependsOn,
					},
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000004"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000005"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000007"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000006"): nil,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000007"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000008"),
						Type:       core.RelationshipDependsOn,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000008"): nil,
			},
			wantVulns: make(map[uuid.UUID][]core.Vulnerability),
		},
		{
			name: "json file created from SBOM file (BOM is empty)",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "report.cdx.json",
				ArtifactType:  artifact.TypeCycloneDX,
				Results: []types.Result{
					{
						Target: "Java",
						Type:   ftypes.Jar,
						Class:  types.ClassLangPkg,
						Packages: []ftypes.Package{
							{
								ID:      "org.apache.logging.log4j:log4j-core:2.23.1",
								Name:    "org.apache.logging.log4j:log4j-core",
								Version: "2.23.1",
								Identifier: ftypes.PkgIdentifier{
									UID: "6C0AE96901617503",
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.apache.logging.log4j",
										Name:      "log4j-core",
										Version:   "2.23.1",
									},
								},
								FilePath: "log4j-core-2.23.1.jar",
							},
						},
					},
				},
			},
			wantComponents: map[uuid.UUID]*core.Component{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): fsComponent,
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): libComponent,
			},
			wantRels: map[uuid.UUID][]core.Relationship{
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000001"): {
					{
						Dependency: uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"),
						Type:       core.RelationshipContains,
					},
				},
				uuid.MustParse("3ff14136-e09f-4df9-80ea-000000000002"): nil,
			},
			wantVulns: make(map[uuid.UUID][]core.Vulnerability),
		},
		{
			name: "invalid digest",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "debian:12",
				ArtifactType:  artifact.TypeContainerImage,
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
				assert.EqualExportedValues(t, *want, *got.Components()[id], id)
			}

			assert.Equal(t, tt.wantRels, got.Relationships())
			assert.Equal(t, tt.wantVulns, got.Vulnerabilities())
		})
	}
}

var (
	appComponent = &core.Component{
		Root: true,
		Type: core.TypeApplication,
		Name: "log4j-core-2.23.1.jar",
	}
	fsComponent = &core.Component{
		Root: true,
		Type: core.TypeFilesystem,
		Name: "report.cdx.json",
		PkgIdentifier: ftypes.PkgIdentifier{
			BOMRef: "3ff14136-e09f-4df9-80ea-000000000001",
		},
		Properties: core.Properties{
			{
				Name:  "SchemaVersion",
				Value: "2",
			},
		},
	}
	libComponent = &core.Component{
		Type:    core.TypeLibrary,
		Name:    "log4j-core",
		Group:   "org.apache.logging.log4j",
		Version: "2.23.1",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:    "6C0AE96901617503",
			BOMRef: "pkg:maven/org.apache.logging.log4j/log4j-core@2.23.1",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.apache.logging.log4j",
				Name:      "log4j-core",
				Version:   "2.23.1",
			},
		},
		Files: []core.File{
			{
				Path: "log4j-core-2.23.1.jar",
			},
		},
		Properties: core.Properties{
			{
				Name:  "FilePath",
				Value: "log4j-core-2.23.1.jar",
			},
			{
				Name:  "PkgID",
				Value: "org.apache.logging.log4j:log4j-core:2.23.1",
			},
			{
				Name:  "PkgType",
				Value: "jar",
			},
		},
	}
)

func newTestBOM(t *testing.T) *core.BOM {
	uuid.SetFakeUUID(t, "2ff14136-e09f-4df9-80ea-%012d")
	bom := core.NewBOM(core.Options{})
	bom.AddComponent(appComponent)
	return bom
}

// BOM without root component
func newTestBOM2(t *testing.T) *core.BOM {
	uuid.SetFakeUUID(t, "2ff14136-e09f-4df9-80ea-%012d")
	bom := core.NewBOM(core.Options{})
	bom.AddComponent(libComponent)
	return bom
}
