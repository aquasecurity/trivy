package alpine

import (
	"errors"
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	type getInput struct {
		osVer   string
		pkgName string
	}
	type getOutput struct {
		advisories []dbTypes.Advisory
		err        error
	}
	type get struct {
		input  getInput
		output getOutput
	}
	type mocks struct {
		get []get
	}

	tests := []struct {
		name    string
		args    args
		mocks   mocks
		want    []types.DetectedVulnerability
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				osVer: "3.10.2",
				pkgs: []ftypes.Package{
					{
						Name:       "ansible",
						Version:    "2.6.4",
						SrcName:    "ansible",
						SrcVersion: "2.6.4",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
					{
						Name:       "invalid",
						Version:    "invalid", // skipped
						SrcName:    "invalid",
						SrcVersion: "invalid",
					},
				},
			},
			mocks: mocks{
				get: []get{
					{
						input: getInput{
							osVer:   "3.10",
							pkgName: "ansible",
						},
						output: getOutput{
							advisories: []dbTypes.Advisory{
								{
									VulnerabilityID: "CVE-2018-10875",
									FixedVersion:    "2.6.3-r0",
								},
								{
									VulnerabilityID: "CVE-2019-10217",
									FixedVersion:    "2.8.4-r0",
								},
								{
									VulnerabilityID: "CVE-2019-INVALID",
									FixedVersion:    "invalid", // skipped
								},
							},
						},
					},
					{
						input: getInput{
							osVer:   "3.10",
							pkgName: "invalid",
						},
						output: getOutput{advisories: []dbTypes.Advisory{{}}},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "ansible",
					VulnerabilityID:  "CVE-2019-10217",
					InstalledVersion: "2.6.4",
					FixedVersion:     "2.8.4-r0",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "contain rc",
			args: args{
				osVer: "3.9",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			mocks: mocks{
				get: []get{
					{
						input: getInput{
							osVer:   "3.9",
							pkgName: "jq",
						},
						output: getOutput{
							advisories: []dbTypes.Advisory{
								{
									VulnerabilityID: "CVE-2016-4074",
									FixedVersion:    "1.6_rc1-r0",
								},
								{
									VulnerabilityID: "CVE-2019-9999",
									FixedVersion:    "1.6_rc2",
								},
							},
						},
					},
					{
						input: getInput{
							osVer:   "3.10",
							pkgName: "invalid",
						},
						output: getOutput{advisories: []dbTypes.Advisory{{}}},
					},
				},
			},
		},
		{
			name: "contain pre",
			args: args{
				osVer: "3.12",
				pkgs: []ftypes.Package{
					{
						Name:       "test",
						Version:    "0.1.0_alpha",
						SrcName:    "test-src",
						SrcVersion: "0.1.0_alpha",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			mocks: mocks{
				get: []get{
					{
						input: getInput{
							osVer:   "3.12",
							pkgName: "test-src",
						},
						output: getOutput{
							advisories: []dbTypes.Advisory{
								{
									VulnerabilityID: "CVE-2030-0001",
									FixedVersion:    "0.1.0_alpha_pre2",
								},
								{
									VulnerabilityID: "CVE-2030-0002",
									FixedVersion:    "0.1.0_alpha2",
								},
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2030-0002",
					PkgName:          "test",
					InstalledVersion: "0.1.0_alpha",
					FixedVersion:     "0.1.0_alpha2",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "Get returns an error",
			args: args{
				osVer: "3.8.1",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			mocks: mocks{
				get: []get{
					{
						input: getInput{
							osVer:   "3.8",
							pkgName: "jq",
						},
						output: getOutput{err: errors.New("error")},
					},
				},
			},
			wantErr: "failed to get alpine advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVulnSrc := new(dbTypes.MockVulnSrc)
			for _, g := range tt.mocks.get {
				mockVulnSrc.On("Get", g.input.osVer, g.input.pkgName).Return(
					g.output.advisories, g.output.err)
			}

			s := &Scanner{
				vs: mockVulnSrc,
			}
			got, err := s.Detect(tt.args.osVer, tt.args.pkgs)

			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}

			assert.ElementsMatch(t, got, tt.want, tt.name)
		})
	}
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		now       time.Time
		osFamily  string
		osVersion string
		expected  bool
	}{
		"alpine3.6": {
			now:       time.Date(2019, 3, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.6",
			expected:  true,
		},
		"alpine3.6 with EOL": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.6.5",
			expected:  false,
		},
		"alpine3.9": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.9.0",
			expected:  true,
		},
		"alpine3.10": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.10",
			expected:  true,
		},
		"unknown": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "unknown",
			expected:  false,
		},
	}

	for testName, v := range vectors {
		s := NewScanner()
		t.Run(testName, func(t *testing.T) {
			actual := s.isSupportedVersion(v.now, v.osFamily, v.osVersion)
			if actual != v.expected {
				t.Errorf("[%s] got %v, want %v", testName, actual, v.expected)
			}
		})
	}
}
