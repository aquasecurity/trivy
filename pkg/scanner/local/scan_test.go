package local

import (
	"context"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

var (
	muslPkg = ftypes.Package{
		Name:       "musl",
		Version:    "1.2.3",
		SrcName:    "musl",
		SrcVersion: "1.2.3",
		Licenses:   []string{"MIT"},
		Layer: ftypes.Layer{
			DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "d9a73c7459d27809",
			PURL: &packageurl.PackageURL{
				Type:      "apk",
				Namespace: "alpine",
				Name:      "musl",
				Version:   "1.2.3",
				Qualifiers: packageurl.Qualifiers{
					packageurl.Qualifier{
						Key:   "distro",
						Value: "3.11",
					},
				},
			},
		},
	}
	railsPkg = ftypes.Package{
		Name:    "rails",
		Version: "4.0.2",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "49be2edc1596dd5d",
			PURL: &packageurl.PackageURL{
				Type:    "gem",
				Name:    "rails",
				Version: "4.0.2",
			},
		},
	}
	innocentPkg = ftypes.Package{
		Name:    "innocent",
		Version: "1.2.3",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "50b49e415e6a2f59",
			PURL: &packageurl.PackageURL{
				Type:    "gem",
				Name:    "innocent",
				Version: "1.2.3",
			},
		},
	}
	uuidPkg = ftypes.Package{
		Name:     "github.com/google/uuid",
		Version:  "1.6.0",
		FilePath: "",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Licenses: []string{"LGPL"},
	}
	urllib3Pkg = ftypes.Package{
		Name:     "urllib3",
		Version:  "3.2.1",
		FilePath: "/usr/lib/python/site-packages/urllib3-3.2.1/METADATA",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Licenses: []string{"MIT"},
	}
	menuinstPkg = ftypes.Package{
		Name:     "menuinst",
		Version:  "2.0.2",
		FilePath: "opt/conda/lib/python3.11/site-packages/menuinst-2.0.2.dist-info/METADATA",
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Licenses: []string{"text://(c) 2016 Continuum Analytics, Inc. / http://continuum.io All Rights Reserved"},
	}

	laravelPkg = ftypes.Package{
		Name:         "laravel/framework",
		Version:      "6.0.0",
		Relationship: ftypes.RelationshipDirect,
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "ba565db6c74968e3",
			PURL: &packageurl.PackageURL{
				Type:      "composer",
				Namespace: "laravel",
				Name:      "framework",
				Version:   "6.0.0",
			},
		},
	}
	guzzlePkg = ftypes.Package{
		Name:         "guzzlehttp/guzzle",
		Version:      "7.9.2",
		Relationship: ftypes.RelationshipIndirect,
		Layer: ftypes.Layer{
			DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
		},
		Identifier: ftypes.PkgIdentifier{
			UID: "791b71e6f31e53a5",
			PURL: &packageurl.PackageURL{
				Type:      "composer",
				Namespace: "guzzlehttp",
				Name:      "guzzle",
				Version:   "7.9.2",
			},
		},
	}
)

func TestScanner_Scan(t *testing.T) {
	type args struct {
		target   string
		layerIDs []string
		options  types.ScanOptions
	}
	tests := []struct {
		name        string
		args        args
		fixtures    []string
		setupCache  func(t *testing.T) cache.Cache
		wantResults types.Results
		wantOS      ftypes.OS
		wantErr     string
	}{
		{
			name: "happy path",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{muslPkg},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{railsPkg},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   ftypes.Alpine,
					Packages: ftypes.Packages{
						muslPkg,
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-9999",
							PkgName:          muslPkg.Name,
							PkgIdentifier:    muslPkg.Identifier,
							InstalledVersion: muslPkg.Version,
							FixedVersion:     "1.2.4",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2020-9999",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "dos",
								Description: "dos vulnerability",
								Severity:    "HIGH",
							},
						},
					},
				},
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Packages: ftypes.Packages{
						railsPkg,
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          railsPkg.Name,
							PkgIdentifier:    railsPkg.Identifier,
							InstalledVersion: railsPkg.Version,
							FixedVersion:     "4.0.3, 3.2.17",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2014-0081",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "xss",
								Description: "xss vulnerability",
								Severity:    "MEDIUM",
								References: []string{
									"http://example.com",
								},
								LastModifiedDate: lo.ToPtr(time.Date(2020, 2, 1, 1, 1, 0, 0, time.UTC)),
								PublishedDate:    lo.ToPtr(time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)),
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   true,
			},
		},
		{
			name: "happy path with OS rewriting",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
					Distro: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{muslPkg},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   ftypes.Alpine,
					Packages: ftypes.Packages{
						muslPkg,
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-9999",
							PkgName:          muslPkg.Name,
							PkgIdentifier:    muslPkg.Identifier,
							InstalledVersion: muslPkg.Version,
							FixedVersion:     "1.2.4",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2020-9999",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "dos",
								Description: "dos vulnerability",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   true,
			},
		},
		{
			name: "happy path license scanner",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.LicenseScanner},
					LicenseFull:      true,
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{
								muslPkg,
							},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.GoModule,
							FilePath: "/app/go.mod",
							Packages: []ftypes.Package{
								uuidPkg,
							},
						},
						{
							Type:     ftypes.PythonPkg,
							FilePath: "",
							Packages: []ftypes.Package{
								urllib3Pkg,
								menuinstPkg,
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "OS Packages",
					Class:  types.ClassLicense,
					Licenses: []types.DetectedLicense{
						{
							Severity:   "UNKNOWN",
							Category:   "unknown",
							PkgName:    muslPkg.Name,
							Name:       "MIT",
							Confidence: 1,
						},
					},
				},
				{
					Target: "/app/go.mod",
					Class:  types.ClassLicense,
					Licenses: []types.DetectedLicense{
						{
							Severity:   "UNKNOWN",
							Category:   "unknown",
							PkgName:    uuidPkg.Name,
							FilePath:   "/app/go.mod",
							Name:       "LGPL",
							Confidence: 1,
							Link:       "",
						},
					},
				},
				{
					Target: "Python",
					Class:  types.ClassLicense,
					Licenses: []types.DetectedLicense{
						{
							Severity:   "UNKNOWN",
							Category:   "unknown",
							PkgName:    urllib3Pkg.Name,
							FilePath:   "/usr/lib/python/site-packages/urllib3-3.2.1/METADATA",
							Name:       "MIT",
							Confidence: 1,
						},
						{
							Severity:   "UNKNOWN",
							Category:   "unknown",
							PkgName:    menuinstPkg.Name,
							FilePath:   "opt/conda/lib/python3.11/site-packages/menuinst-2.0.2.dist-info/METADATA",
							Name:       "CUSTOM License: (c) 2016 Continuum...",
							Text:       "(c) 2016 Continuum Analytics, Inc. / http://continuum.io All Rights Reserved",
							Confidence: 1,
						},
					},
				},
				{
					Target: "Loose File License(s)",
					Class:  types.ClassLicenseFile,
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   false,
			},
		},
		{
			name: "happy path with empty os",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app1/Gemfile.lock",
							Packages: []ftypes.Package{
								innocentPkg, // no vulnerability
							},
						},
						{
							Type:     ftypes.Bundler,
							FilePath: "/app2/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg, // one vulnerability
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "/app1/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Packages: ftypes.Packages{
						innocentPkg,
					},
				},
				{
					Target: "/app2/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Packages: ftypes.Packages{
						railsPkg,
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          railsPkg.Name,
							PkgIdentifier:    railsPkg.Identifier,
							InstalledVersion: railsPkg.Version,
							FixedVersion:     "4.0.3, 3.2.17",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2014-0081",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "xss",
								Description: "xss vulnerability",
								Severity:    "MEDIUM",
								References: []string{
									"http://example.com",
								},
								LastModifiedDate: lo.ToPtr(time.Date(2020, 2, 1, 1, 1, 0, 0, time.UTC)),
								PublishedDate:    lo.ToPtr(time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)),
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{},
		},
		{
			name: "happy path, empty file paths (e.g. Scanned SBOM)",
			args: args{
				target:   "./result.cdx",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes:            []string{types.PkgTypeLibrary},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
						{
							Type:     ftypes.Composer,
							FilePath: "",
							Packages: []ftypes.Package{
								laravelPkg,
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Packages: []ftypes.Package{
						{
							Name:       railsPkg.Name,
							Version:    railsPkg.Version,
							Identifier: railsPkg.Identifier,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          railsPkg.Name,
							PkgIdentifier:    railsPkg.Identifier,
							InstalledVersion: railsPkg.Version,
							FixedVersion:     "4.0.3, 3.2.17",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2014-0081",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "xss",
								Description: "xss vulnerability",
								Severity:    "MEDIUM",
								References: []string{
									"http://example.com",
								},
								LastModifiedDate: lo.ToPtr(time.Date(2020, 2, 1, 1, 1, 0, 0, time.UTC)),
								PublishedDate:    lo.ToPtr(time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)),
							},
						},
					},
				},
				{
					Target: "",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Composer,
					Packages: []ftypes.Package{
						{
							Name:         laravelPkg.Name,
							Version:      laravelPkg.Version,
							Identifier:   laravelPkg.Identifier,
							Relationship: ftypes.RelationshipDirect,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2021-21263",
							PkgName:          laravelPkg.Name,
							PkgIdentifier:    laravelPkg.Identifier,
							InstalledVersion: laravelPkg.Version,
							FixedVersion:     "8.22.1, 7.30.3, 6.20.12",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with no package",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					Applications: []ftypes.Application{
						{
							Type:     "bundler",
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   ftypes.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Packages: ftypes.Packages{
						railsPkg,
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							PkgIdentifier:    railsPkg.Identifier,
							InstalledVersion: railsPkg.Version,
							FixedVersion:     "4.0.3, 3.2.17",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2014-0081",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "xss",
								Description: "xss vulnerability",
								Severity:    "MEDIUM",
								References: []string{
									"http://example.com",
								},
								LastModifiedDate: lo.ToPtr(time.Date(2020, 2, 1, 1, 1, 0, 0, time.UTC)),
								PublishedDate:    lo.ToPtr(time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)),
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   true,
			},
		},
		{
			name: "happy path with unsupported os",
			args: args{
				target:   "fedora:27",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships:    ftypes.Relationships,
					Scanners:            types.Scanners{types.VulnerabilityScanner},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: "fedora",
						Name:   "27",
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target:   "/app/Gemfile.lock",
					Class:    types.ClassLangPkg,
					Type:     ftypes.Bundler,
					Packages: ftypes.Packages{railsPkg},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          railsPkg.Name,
							PkgIdentifier:    railsPkg.Identifier,
							InstalledVersion: railsPkg.Version,
							FixedVersion:     "4.0.3, 3.2.17",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2014-0081",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "xss",
								Description: "xss vulnerability",
								Severity:    "MEDIUM",
								References: []string{
									"http://example.com",
								},
								LastModifiedDate: lo.ToPtr(time.Date(2020, 2, 1, 1, 1, 0, 0, time.UTC)),
								PublishedDate:    lo.ToPtr(time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)),
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "fedora",
				Name:   "27",
			},
		},
		{
			name: "happy path with a scratch image",
			args: args{
				target:   "busybox:latest",
				layerIDs: []string{"sha256:a6d503001157aedc826853f9b67f26d35966221b158bff03849868ae4a821116"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:a6d503001157aedc826853f9b67f26d35966221b158bff03849868ae4a821116", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS:            ftypes.OS{},
				}))
				return c
			},
			wantResults: nil,
		},
		{
			name: "happy path with only language-specific package detection, excluding direct packages",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33"},
				options: types.ScanOptions{
					PkgTypes: []string{types.PkgTypeLibrary},
					PkgRelationships: []ftypes.Relationship{
						ftypes.RelationshipUnknown,
						ftypes.RelationshipRoot,
						ftypes.RelationshipIndirect,
					},
					Scanners:            types.Scanners{types.VulnerabilityScanner},
					VulnSeveritySources: []dbTypes.SourceID{"auto"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					PackageInfos: []ftypes.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []ftypes.Package{muslPkg},
						},
					},
					Applications: []ftypes.Application{
						{
							Type:     "bundler",
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								railsPkg,
							},
						},
						{
							Type:     "composer",
							FilePath: "/app/composer-lock.json",
							Packages: []ftypes.Package{
								laravelPkg, // will be excluded
								guzzlePkg,
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target:   "/app/Gemfile.lock",
					Class:    types.ClassLangPkg,
					Type:     ftypes.Bundler,
					Packages: ftypes.Packages{railsPkg},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          railsPkg.Name,
							PkgIdentifier:    railsPkg.Identifier,
							InstalledVersion: railsPkg.Version,
							FixedVersion:     "4.0.3, 3.2.17",
							Status:           dbTypes.StatusFixed,
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
							PrimaryURL: "https://avd.aquasec.com/nvd/cve-2014-0081",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "xss",
								Description: "xss vulnerability",
								Severity:    "MEDIUM",
								References: []string{
									"http://example.com",
								},
								LastModifiedDate: lo.ToPtr(time.Date(2020, 2, 1, 1, 1, 0, 0, time.UTC)),
								PublishedDate:    lo.ToPtr(time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)),
							},
						},
					},
				},
				{
					Target:   "/app/composer-lock.json",
					Class:    types.ClassLangPkg,
					Type:     ftypes.Composer,
					Packages: ftypes.Packages{guzzlePkg},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
			},
		},
		{
			name: "happy path with misconfigurations",
			args: args{
				target:   "/app/configs",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					Scanners: types.Scanners{types.MisconfigScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					DiffID:        "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					Misconfigurations: []ftypes.Misconfiguration{
						{
							FileType: ftypes.Kubernetes,
							FilePath: "/app/configs/pod.yaml",
							Warnings: []ftypes.MisconfResult{
								{
									Namespace: "main.kubernetes.id300",
									PolicyMetadata: ftypes.PolicyMetadata{
										ID:       "ID300",
										Type:     "Kubernetes Security Check",
										Title:    "Bad Deployment",
										Severity: "DUMMY",
									},
								},
							},
						},
						{
							FileType: ftypes.Kubernetes,
							FilePath: "/app/configs/deployment.yaml",
							Successes: []ftypes.MisconfResult{
								{
									Namespace: "builtin.kubernetes.id200",
									PolicyMetadata: ftypes.PolicyMetadata{
										ID:       "ID200",
										Type:     "Kubernetes Security Check",
										Title:    "Bad Deployment",
										Severity: "MEDIUM",
									},
								},
							},
							Failures: ftypes.MisconfResults{
								{
									Namespace: "main.kubernetes.id100",
									Message:   "something bad",
									PolicyMetadata: ftypes.PolicyMetadata{
										ID:       "ID100",
										Type:     "Kubernetes Security Check",
										Title:    "Bad Deployment",
										Severity: "HIGH",
									},
								},
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "/app/configs/deployment.yaml",
					Class:  types.ClassConfig,
					Type:   ftypes.Kubernetes,
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:      "Kubernetes Security Check",
							ID:        "ID100",
							Title:     "Bad Deployment",
							Message:   "something bad",
							Namespace: "main.kubernetes.id100",
							Severity:  "HIGH",
							Status:    types.MisconfStatusFailure,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
							CauseMetadata: ftypes.CauseMetadata{
								Provider: "",
								Service:  "",
								Code:     ftypes.Code{},
							},
						},
						{
							Type:       "Kubernetes Security Check",
							ID:         "ID200",
							Title:      "Bad Deployment",
							Message:    "No issues found",
							Namespace:  "builtin.kubernetes.id200",
							Severity:   "MEDIUM",
							PrimaryURL: "https://avd.aquasec.com/misconfig/id200",
							References: []string{
								"https://avd.aquasec.com/misconfig/id200",
							},
							Status: types.MisconfStatusPassed,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
							CauseMetadata: ftypes.CauseMetadata{
								Provider: "",
								Service:  "",
								Code:     ftypes.Code{},
							},
						},
					},
				},
				{
					Target: "/app/configs/pod.yaml",
					Class:  types.ClassConfig,
					Type:   ftypes.Kubernetes,
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:      "Kubernetes Security Check",
							ID:        "ID300",
							Title:     "Bad Deployment",
							Message:   "No issues found",
							Namespace: "main.kubernetes.id300",
							Severity:  "MEDIUM",
							Status:    types.MisconfStatusFailure,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   false,
			},
		},
		{
			name: "sad path: ApplyLayers returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes: []string{
						types.PkgTypeOS,
						types.PkgTypeLibrary,
					},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: 0,
				}))
				return c
			},
			wantErr: "failed to apply layers",
		},
		{
			name: "sad path: library.Detect returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					PkgTypes:         []string{types.PkgTypeLibrary},
					PkgRelationships: ftypes.Relationships,
					Scanners:         types.Scanners{types.VulnerabilityScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: "alpine",
						Name:   "3.11",
					},
					Applications: []ftypes.Application{
						{
							Type:     ftypes.Bundler,
							FilePath: "/app/Gemfile.lock",
							Packages: []ftypes.Package{
								{
									Name:    "rails",
									Version: "6.0",
									Layer: ftypes.Layer{
										DiffID: "sha256:9bdb2c849099a99c8ab35f6fd7469c623635e8f4479a0a5a3df61e22bae509f6",
									},
								},
							},
						},
					},
				}))
				return c
			},
			wantErr: "failed to scan application libraries",
		},
		{
			name: "scan image history",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					ImageConfigScanners: types.Scanners{types.MisconfigScanner},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutBlob("sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10", ftypes.BlobInfo{
					SchemaVersion: ftypes.BlobJSONSchemaVersion,
					OS: ftypes.OS{
						Family: ftypes.Alpine,
						Name:   "3.11",
					},
					Misconfigurations: []ftypes.Misconfiguration{
						{
							FileType: ftypes.Dockerfile,
							FilePath: "Dockerfile",
							Successes: ftypes.MisconfResults{
								{
									Namespace: "builtin.dockerfile.DS001",
									Query:     "data.builtin.dockerfile.DS001.deny",
									Message:   "",
									PolicyMetadata: ftypes.PolicyMetadata{
										ID:                 "DS001",
										AVDID:              "AVD-DS-0001",
										Type:               "Dockerfile Security Check",
										Title:              "':latest' tag used",
										Description:        "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
										Severity:           "MEDIUM",
										RecommendedActions: "Add a tag to the image in the 'FROM' statement",
									},
									CauseMetadata: ftypes.CauseMetadata{
										Provider: "Dockerfile",
										Service:  "general",
										Code:     ftypes.Code{},
									},
								},
							},
							Failures: ftypes.MisconfResults{
								{
									Namespace: "builtin.dockerfile.DS002",
									Query:     "data.builtin.dockerfile.DS002.deny",
									Message:   "Specify at least 1 USER command in Dockerfile with non-root user as argument",
									PolicyMetadata: ftypes.PolicyMetadata{
										ID:                 "DS002",
										AVDID:              "AVD-DS-0002",
										Type:               "Dockerfile Security Check",
										Title:              "Image user should not be 'root'",
										Description:        "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
										Severity:           "HIGH",
										RecommendedActions: "Add 'USER <non root user name>' line to the Dockerfile",
									},
									CauseMetadata: ftypes.CauseMetadata{
										Provider: "Dockerfile",
										Service:  "general",
										Code:     ftypes.Code{},
									},
								},
							},
						},
					},
				}))
				return c
			},
			wantResults: types.Results{
				{
					Target: "Dockerfile",
					Class:  types.ClassConfig,
					Type:   ftypes.Dockerfile,
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Namespace:   "builtin.dockerfile.DS002",
							Query:       "data.builtin.dockerfile.DS002.deny",
							Message:     "Specify at least 1 USER command in Dockerfile with non-root user as argument",
							Type:        "Dockerfile Security Check",
							ID:          "DS002",
							AVDID:       "AVD-DS-0002",
							Title:       "Image user should not be 'root'",
							Description: "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
							Severity:    "HIGH",
							Resolution:  "Add 'USER <non root user name>' line to the Dockerfile",
							Status:      types.MisconfStatusFailure,
							PrimaryURL:  "https://avd.aquasec.com/misconfig/ds002",
							References:  []string{"https://avd.aquasec.com/misconfig/ds002"},
							CauseMetadata: ftypes.CauseMetadata{
								Provider: "Dockerfile",
								Service:  "general",
								Code:     ftypes.Code{},
							},
						},
						{
							Namespace:   "builtin.dockerfile.DS001",
							Query:       "data.builtin.dockerfile.DS001.deny",
							Message:     "No issues found",
							Type:        "Dockerfile Security Check",
							ID:          "DS001",
							AVDID:       "AVD-DS-0001",
							Title:       "':latest' tag used",
							Description: "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
							Severity:    "MEDIUM",
							Resolution:  "Add a tag to the image in the 'FROM' statement",
							Status:      types.MisconfStatusPassed,
							CauseMetadata: ftypes.CauseMetadata{
								Provider: "Dockerfile",
								Service:  "general",
								Code:     ftypes.Code{},
							},
							PrimaryURL: "https://avd.aquasec.com/misconfig/ds001",
							References: []string{"https://avd.aquasec.com/misconfig/ds001"},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			c := tt.setupCache(t)
			a := applier.NewApplier(c)
			s := NewScanner(a, ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))

			gotResults, gotOS, err := s.Scan(context.Background(), tt.args.target, "", tt.args.layerIDs, tt.args.options)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.wantResults, gotResults)
			assert.Equal(t, tt.wantOS, gotOS)
		})
	}
}
