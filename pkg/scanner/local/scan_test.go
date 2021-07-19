package local

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	ftypes "github.com/aquasecurity/fanal/types"
	dtypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Scan(t *testing.T) {
	type args struct {
		target   string
		layerIDs []string
		options  types.ScanOptions
	}
	tests := []struct {
		name                    string
		args                    args
		fixtures                []string
		applyLayersExpectation  ApplierApplyLayersExpectation
		ospkgDetectExpectations []OspkgDetectorDetectExpectation
		wantResults             report.Results
		wantOS                  *ftypes.OS
		wantEosl                bool
		wantErr                 string
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
						OS: &ftypes.OS{
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
								Type:     ftypes.Bundler,
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "4.0.2"},
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
			ospkgDetectExpectations: []OspkgDetectorDetectExpectation{
				{
					Args: OspkgDetectorDetectArgs{
						OsFamily: "alpine",
						OsName:   "3.11",
						Pkgs: []ftypes.Package{
							{
								Name:    "musl",
								Version: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
					},
					Returns: OspkgDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-9999",
								PkgName:          "musl",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Eosl: false,
					},
				},
			},
			wantResults: report.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-9999",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
					},
					Class: report.ClassOSPkg,
					Type:  vulnerability.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Class: report.ClassLangPkg,
					Type:  ftypes.Bundler,
				},
			},
			wantOS: &ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
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
						OS: &ftypes.OS{
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
							{
								Name:    "ausl",
								Version: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "4.0.2"},
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
			ospkgDetectExpectations: []OspkgDetectorDetectExpectation{
				{
					Args: OspkgDetectorDetectArgs{
						OsFamily: "alpine",
						OsName:   "3.11",
						Pkgs: []ftypes.Package{
							{
								Name:    "musl",
								Version: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
							{
								Name:    "ausl",
								Version: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
					},
					Returns: OspkgDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-9999",
								PkgName:          "musl",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
						Eosl: false,
					},
				},
			},
			wantResults: report.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Packages: []ftypes.Package{
						{
							Name:    "ausl",
							Version: "1.2.3",
							Layer: ftypes.Layer{
								DiffID: "sha256:bbf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
						{
							Name:    "musl",
							Version: "1.2.3",
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-9999",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Layer: ftypes.Layer{
								DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
							},
						},
					},
					Class: report.ClassOSPkg,
					Type:  vulnerability.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Packages: []ftypes.Package{
						{
							Name:    "rails",
							Version: "4.0.2",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Class: report.ClassLangPkg,
					Type:  ftypes.Bundler,
				},
			},
			wantOS: &ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
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
						OS: &ftypes.OS{},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "4.0.2"},
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
			wantResults: report.Results{
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
					Class: report.ClassLangPkg,
					Type:  "bundler",
				},
			},
			wantOS: &ftypes.OS{},
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
						OS: &ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "4.0.2"},
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
			ospkgDetectExpectations: []OspkgDetectorDetectExpectation{
				{
					Args: OspkgDetectorDetectArgs{
						OsFamily: "alpine",
						OsName:   "3.11",
					},
					Returns: OspkgDetectorDetectReturns{
						Eosl: false,
					},
				},
			},
			wantResults: report.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Class:  report.ClassOSPkg,
					Type:   vulnerability.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Class: report.ClassLangPkg,
					Type:  "bundler",
				},
			},
			wantOS: &ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
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
						OS: &ftypes.OS{
							Family: "fedora",
							Name:   "27",
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "4.0.2"},
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
			ospkgDetectExpectations: []OspkgDetectorDetectExpectation{
				{
					Args: OspkgDetectorDetectArgs{
						OsFamily: "fedora",
						OsName:   "27",
					},
					Returns: OspkgDetectorDetectReturns{
						Err: ospkgDetector.ErrUnsupportedOS,
					},
				},
			},
			wantResults: report.Results{
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
					Class: report.ClassLangPkg,
					Type:  ftypes.Bundler,
				},
			},
			wantOS: &ftypes.OS{
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
					Detail: ftypes.ArtifactDetail{
						OS: nil,
					},
					Err: analyzer.ErrUnknownOS,
				},
			},
			wantResults: nil,
			wantOS:      nil,
		},
		{
			name: "happy path with only library detection",
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
						OS: &ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{Name: "musl", Version: "1.2.3"},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "/app/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "4.0.2"},
										Layer: ftypes.Layer{
											DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
										},
									},
								},
							},
							{
								Type:     "composer",
								FilePath: "/app/composer-lock.json",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "laravel/framework", Version: "6.0.0"},
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
			wantResults: report.Results{
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2014-0081",
							PkgName:          "rails",
							InstalledVersion: "4.0.2",
							FixedVersion:     "4.0.3, 3.2.17",
							Layer: ftypes.Layer{
								DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
							},
						},
					},
					Class: report.ClassLangPkg,
					Type:  ftypes.Bundler,
				},
				{
					Target: "/app/composer-lock.json",
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
					Class: report.ClassLangPkg,
					Type:  ftypes.Composer,
				},
			},
			wantOS: &ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
			},
		},
		{
			name: "happy path with skip directories",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType:       []string{types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability, types.SecurityCheckConfig},
					SkipDirs:       []string{"/usr/lib/ruby/gems", "/app/k8s"},
				},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			applyLayersExpectation: ApplierApplyLayersExpectation{
				Args: ApplierApplyLayersArgs{
					BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				},
				Returns: ApplierApplyLayersReturns{
					Detail: ftypes.ArtifactDetail{
						OS: &ftypes.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Packages: []ftypes.Package{
							{Name: "musl", Version: "1.2.3"},
						},
						Applications: []ftypes.Application{
							{
								Type:     "bundler",
								FilePath: "usr/lib/ruby/gems/2.5.0/gems/http_parser.rb-0.6.0/Gemfile.lock",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "5.1"},
										Layer: ftypes.Layer{
											DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
										},
									},
								},
							},
							{
								Type:     "composer",
								FilePath: "app/composer-lock.json",
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "laravel/framework", Version: "6.0.0"},
										Layer: ftypes.Layer{
											DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
										},
									},
								},
							},
						},
						Misconfigurations: []ftypes.Misconfiguration{
							{
								FileType: ftypes.Kubernetes,
								FilePath: "/app/k8s/deployment.yaml",
								Failures: ftypes.MisconfResults{
									{
										Namespace: "appshield.kubernetes.id100",
										Message:   "something bad",
									},
								},
							},
						},
					},
				},
			},
			wantResults: report.Results{
				{
					Target: "app/composer-lock.json",
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
					Class: report.ClassLangPkg,
					Type:  ftypes.Composer,
				},
			},
			wantOS: &ftypes.OS{
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
										Namespace: "appshield.kubernetes.id200",
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
			wantResults: report.Results{
				{
					Target: "/app/configs/deployment.yaml",
					Class:  report.ClassConfig,
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
							Namespace:  "appshield.kubernetes.id200",
							Severity:   "MEDIUM",
							PrimaryURL: "https://avd.aquasec.com/appshield/id200",
							References: []string{
								"https://avd.aquasec.com/appshield/id200",
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
					Class:  report.ClassConfig,
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
			name: "sad path: ospkgDetector.Detect returns an error",
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
						OS: &ftypes.OS{
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
					},
				},
			},
			ospkgDetectExpectations: []OspkgDetectorDetectExpectation{
				{
					Args: OspkgDetectorDetectArgs{
						OsFamily: "alpine",
						OsName:   "3.11",
						Pkgs: []ftypes.Package{
							{
								Name:    "musl",
								Version: "1.2.3",
								Layer: ftypes.Layer{
									DiffID: "sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
								},
							},
						},
					},
					Returns: OspkgDetectorDetectReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to scan OS packages",
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
						OS: &ftypes.OS{
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
								Libraries: []ftypes.LibraryInfo{
									{
										Library: dtypes.Library{Name: "rails", Version: "6.0"},
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

			ospkgDetector := new(MockOspkgDetector)
			ospkgDetector.ApplyDetectExpectations(tt.ospkgDetectExpectations)

			s := NewScanner(applier, ospkgDetector)
			gotResults, gotOS, gotEosl, err := s.Scan(tt.args.target, "", tt.args.layerIDs, tt.args.options)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantResults, gotResults)
			assert.Equal(t, tt.wantOS, gotOS)
			assert.Equal(t, tt.wantEosl, gotEosl)

			applier.AssertExpectations(t)
			ospkgDetector.AssertExpectations(t)
		})
	}
}

func Test_skipped(t *testing.T) {
	type args struct {
		filePath  string
		skipFiles []string
		skipDirs  []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "no skip directory",
			args: args{
				filePath: "app/Gemfile.lock",
				skipDirs: []string{},
			},
			want: false,
		},
		{
			name: "skip directory with the leading slash",
			args: args{
				filePath: "app/Gemfile.lock",
				skipDirs: []string{"/app"},
			},
			want: true,
		},
		{
			name: "skip directory without a slash",
			args: args{
				filePath: "usr/lib/ruby/gems/2.5.0/gems/http_parser.rb-0.6.0/Gemfile.lock",
				skipDirs: []string{"/usr/lib/ruby"},
			},
			want: true,
		},
		{
			name: "skip file with the leading slash",
			args: args{
				filePath:  "Gemfile.lock",
				skipFiles: []string{"/Gemfile.lock"},
			},
			want: true,
		},
		{
			name: "skip file without a slash",
			args: args{
				filePath:  "Gemfile.lock",
				skipFiles: []string{"Gemfile.lock"},
			},
			want: true,
		},
		{
			name: "not skipped",
			args: args{
				filePath: "usr/lib/ruby/gems/2.5.0/gems/http_parser.rb-0.6.0/Gemfile.lock",
				skipDirs: []string{"lib/ruby"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := skipped(tt.args.filePath, tt.args.skipFiles, tt.args.skipDirs)
			assert.Equal(t, tt.want, got)
		})
	}
}
