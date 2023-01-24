package local

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

func TestScanner_Scan(t *testing.T) {
	type args struct {
		target   string
		layerIDs []string
		options  types.ScanOptions
	}
	tests := []struct {
		name                   string
		args                   args
		fixtures               []string
		applyLayersExpectation ApplierApplyLayersExpectation
		wantResults            types.Results
		wantOS                 ftypes.OS
		wantErr                string
	}{
		{
			name: "happy path",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: fos.Alpine,
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{
								Name:       "musl",
								Version:    "1.2.3",
								SrcName:    "musl",
								SrcVersion: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     ftypes.Bundler,
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails",
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
										},
									},
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   fos.Alpine,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-9999",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
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
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
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
			name: "happy path with list all packages",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:        []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks:  []string{types.SecurityCheckVulnerability},
					ListAllPackages: true,
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{
								Name:       "musl",
								Version:    "1.2.3",
								SrcName:    "musl",
								SrcVersion: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
							{
								Name:       "ausl",
								Version:    "1.2.3",
								SrcName:    "ausl",
								SrcVersion: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails",
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
										},
									},
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   fos.Alpine,
					Packages: []ftypes.Package{
						{
							Name:       "ausl",
							Version:    "1.2.3",
							SrcName:    "ausl",
							SrcVersion: "1.2.3",
							Layer: ftypes.Layer{
								DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
						{
							Name:       "musl",
							Version:    "1.2.3",
							SrcName:    "musl",
							SrcVersion: "1.2.3",
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
					},
					// For backward compatibility, will be removed
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-9999",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
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
					Packages: []ftypes.Package{
						{
							Name:    "rails",
							Version: "4.0.2",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					// For backward compatibility, will be removed
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
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
			name: "happy path with list all packages and without vulnerabilities",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:        []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks:  []string{types.SecurityCheckVulnerability},
					ListAllPackages: true,
				},
			},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{
								Name:       "musl",
								Version:    "1.2.3",
								SrcName:    "musl",
								SrcVersion: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
							{
								Name:       "ausl",
								Version:    "1.2.3",
								SrcName:    "ausl",
								SrcVersion: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails",
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
										},
									},
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   fos.Alpine,
					Packages: []ftypes.Package{
						{
							Name:       "ausl",
							Version:    "1.2.3",
							SrcName:    "ausl",
							SrcVersion: "1.2.3",
							Layer: ftypes.Layer{
								DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
						{
							Name:       "musl",
							Version:    "1.2.3",
							SrcName:    "musl",
							SrcVersion: "1.2.3",
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
					},
				},
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Packages: []ftypes.Package{
						{
							Name:    "rails",
							Version: "4.0.2",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
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
			name: "happy path with empty os",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{},
						Applications: []ftypes.Application{
							{
								Type:     ftypes.Bundler,
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "innocent", // no vulnerability
										Version: "1.2.3",
										Layer: ftypes.Layer{
											DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
										},
									},
								},
							},
							{
								Type:     ftypes.Bundler,
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails", // one vulnerability
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
										},
									},
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   "bundler",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
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
			name: "happy path with no package",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails",
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
										},
									},
								},
							},
						},
					},
					Err: analyzer.ErrNoPkgsDetected,
				},
			},
			wantResults: types.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  types.ClassOSPkg,
					Type:   fos.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
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
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: "fedora",
							Name:   "27",
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails",
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
										},
									},
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
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
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:a6d503001157aedc826853f9b67f26d35966221b158bff03849868ae4a821116"},
				},
				Returns: ApplierApplyLayersReturns{
					Err: analyzer.ErrUnknownOS,
				},
			},
			wantResults: nil,
		},
		{
			name: "happy path with only language-specific package detection",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{
								Name:       "musl",
								Version:    "1.2.3",
								SrcName:    "musl",
								SrcVersion: "1.2.3",
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
									{
										Name:    "rails",
										Version: "4.0.2",
										Layer: ftypes.Layer{
											DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
										},
									},
								},
							},
							{
								Type:     "composer",
								FilePath: "/app/composer-lock.json",
								Libraries: []ftypes.Package{
									{
										Name:    "laravel/framework",
										Version: "6.0.0",
										Layer: ftypes.Layer{
											DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
										},
									},
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "/app/Gemfile.lock",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Bundler,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
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
					Target: "/app/composer-lock.json",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Composer,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2021-21263",
							PkgName:          "laravel/framework",
							InstalledVersion: "6.0.0",
							FixedVersion:     "8.22.1, 7.30.3, 6.20.12",
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
			},
		},
		{
			name: "happy path with misconfigurations",
			args: args{
				target:   "/app/configs",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					SecurityChecks: []string{types.SecurityCheckConfig},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
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
								Exceptions: ftypes.MisconfResults{
									{
										Namespace: "main.kubernetes.id100",
										PolicyMetadata: ftypes.PolicyMetadata{
											ID:       "ID100",
											Type:     "Kubernetes Security Check",
											Title:    "Bad Deployment",
											Severity: "HIGH",
										},
									},
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
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
								Layer: ftypes.Layer{
									DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
								},
							},
						},
					},
				},
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
							Status:    types.StatusFailure,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
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
							Status: types.StatusPassed,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
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
							Status:    types.StatusFailure,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
						{
							Type:      "Kubernetes Security Check",
							ID:        "ID100",
							Title:     "Bad Deployment",
							Message:   "No issues found",
							Namespace: "main.kubernetes.id100",
							Severity:  "HIGH",
							Status:    types.StatusException,
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
				},
			},
		},
		{
			name: "sad path: ApplyLayers returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to apply layers",
		},
		{
			name: "sad path: library.Detect returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
			},
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{
								Name:    "musl",
								Version: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.Package{
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
					},
				},
			},
			wantErr: "failed to scan application libraries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			applier := new(MockApplier)
			applier.ApplyApplyLayersExpectation(tt.applyLayersExpectation)

			s := NewScanner(applier, ospkg.Detector{}, vulnerability.NewClient(db.Config{}))
			gotResults, gotOS, err := s.Scan(context.Background(), tt.args.target, "", tt.args.layerIDs, tt.args.options)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.wantResults, gotResults)
			assert.Equal(t, tt.wantOS, gotOS)

			applier.AssertExpectations(t)
		})
	}
}
