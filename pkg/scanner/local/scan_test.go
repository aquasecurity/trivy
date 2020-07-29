package local

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	ftypes "github.com/aquasecurity/fanal/types"
	dtypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
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
		applyLayersExpectation  ApplierApplyLayersExpectation
		ospkgDetectExpectations []OspkgDetectorDetectExpectation
		libDetectExpectations   []LibraryDetectorDetectExpectation
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
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "6.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-10000",
								PkgName:          "rails",
								InstalledVersion: "6.0",
								FixedVersion:     "6.1",
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
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
					Type: vulnerability.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-10000",
							PkgName:          "rails",
							InstalledVersion: "6.0",
							FixedVersion:     "6.1",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Type: "bundler",
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
				options:  types.ScanOptions{VulnType: []string{"os", "library"}, ListAllPackages: true},
			},
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
										Library: dtypes.Library{Name: "rails", Version: "6.0"},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "6.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-10000",
								PkgName:          "rails",
								InstalledVersion: "6.0",
								FixedVersion:     "6.1",
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
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
					Type: vulnerability.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Packages: []ftypes.Package{
						{
							Name:    "rails",
							Version: "6.0",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-10000",
							PkgName:          "rails",
							InstalledVersion: "6.0",
							FixedVersion:     "6.1",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Type: "bundler",
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
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
										Library: dtypes.Library{Name: "rails", Version: "6.0"},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "6.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-10000",
								PkgName:          "rails",
								InstalledVersion: "6.0",
								FixedVersion:     "6.1",
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
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-10000",
							PkgName:          "rails",
							InstalledVersion: "6.0",
							FixedVersion:     "6.1",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
					Type: "bundler",
				},
			},
			wantOS: &ftypes.OS{},
		},
		{
			name: "happy path with no package",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
										Library: dtypes.Library{Name: "rails", Version: "6.0"},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "6.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-10000",
								PkgName:          "rails",
								InstalledVersion: "6.0",
								FixedVersion:     "6.1",
								Layer: ftypes.Layer{
									DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
								},
							},
						},
					},
				},
			},
			wantResults: report.Results{
				{
					Target: "alpine:latest (alpine 3.11)",
					Type:   vulnerability.Alpine,
				},
				{
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-10000",
							PkgName:          "rails",
							InstalledVersion: "6.0",
							FixedVersion:     "6.1",
							Layer: ftypes.Layer{
								DiffID: "sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
							},
						},
					},
					Type: "bundler",
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
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
										Library: dtypes.Library{Name: "rails", Version: "6.0"},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "6.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-10000",
								PkgName:          "rails",
								InstalledVersion: "6.0",
								FixedVersion:     "6.1",
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
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-10000",
							PkgName:          "rails",
							InstalledVersion: "6.0",
							FixedVersion:     "6.1",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
					Type: "bundler",
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
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
				options:  types.ScanOptions{VulnType: []string{"library"}},
			},
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
										Library: dtypes.Library{Name: "rails", Version: "5.1"},
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
										Library: dtypes.Library{Name: "laravel", Version: "6.0.0"},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "5.1"},
								Layer: ftypes.Layer{
									DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-11111",
								PkgName:          "rails",
								InstalledVersion: "5.1",
								FixedVersion:     "5.2",
								Layer: ftypes.Layer{
									DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
								},
							},
						},
					},
				},
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/composer-lock.json",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "laravel", Version: "6.0.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						DetectedVulns: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-22222",
								PkgName:          "laravel",
								InstalledVersion: "6.0.0",
								FixedVersion:     "6.1.0",
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
					Target: "/app/Gemfile.lock",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-11111",
							PkgName:          "rails",
							InstalledVersion: "5.1",
							FixedVersion:     "5.2",
							Layer: ftypes.Layer{
								DiffID: "sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
							},
						},
					},
					Type: "bundler",
				},
				{
					Target: "/app/composer-lock.json",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-22222",
							PkgName:          "laravel",
							InstalledVersion: "6.0.0",
							FixedVersion:     "6.1.0",
							Layer: ftypes.Layer{
								DiffID: "sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
							},
						},
					},
					Type: "composer",
				},
			},
			wantOS: &ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
			},
		},
		{
			name: "sad path: ApplyLayers returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
				options:  types.ScanOptions{VulnType: []string{"os", "library"}},
			},
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
			name: "sad path: libDetector.Detect returns an error",
			args: args{
				target:   "alpine:latest",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options:  types.ScanOptions{VulnType: []string{"library"}},
			},
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
			libDetectExpectations: []LibraryDetectorDetectExpectation{
				{
					Args: LibraryDetectorDetectArgs{
						FilePath: "/app/Gemfile.lock",
						Pkgs: []ftypes.LibraryInfo{
							{
								Library: dtypes.Library{Name: "rails", Version: "6.0"},
								Layer: ftypes.Layer{
									DiffID: "sha256:9bdb2c849099a99c8ab35f6fd7469c623635e8f4479a0a5a3df61e22bae509f6",
								},
							},
						},
					},
					Returns: LibraryDetectorDetectReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to scan application libraries",
		},
	}

	log.InitLogger(false, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applier := new(MockApplier)
			applier.ApplyApplyLayersExpectation(tt.applyLayersExpectation)

			ospkgDetector := new(MockOspkgDetector)
			ospkgDetector.ApplyDetectExpectations(tt.ospkgDetectExpectations)

			libDetector := new(MockLibraryDetector)
			libDetector.ApplyDetectExpectations(tt.libDetectExpectations)

			s := NewScanner(applier, ospkgDetector, libDetector)
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
			libDetector.AssertExpectations(t)
		})
	}
}
