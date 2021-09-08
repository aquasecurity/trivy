package alma

import (
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
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
				osVer: "8.4",
				pkgs: []ftypes.Package{
					{
						Name:            "python3-libs",
						Epoch:           0,
						Version:         "3.6.8",
						Release:         "36.el8.alma",
						Arch:            "x86_64",
						SrcName:         "python3",
						SrcEpoch:        0,
						SrcVersion:      "3.6.8",
						SrcRelease:      "36.el8.alma",
						Modularitylabel: "",
						License:         "Python",
						Layer:           ftypes.Layer{},
					},
				},
			},
			mocks: mocks{
				get: []get{
					{
						input: getInput{
							osVer:   "8.4",
							pkgName: "python3-libs",
						},
						output: getOutput{
							advisories: []dbTypes.Advisory{
								{
									VulnerabilityID: "CVE-2019-16935",
									FixedVersion:    "3.6.8-31.el8.alma",
								},
								{
									VulnerabilityID: "CVE-2020-26116",
									FixedVersion:    "3.6.8-37.el8.alma",
								},
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "python3-libs",
					VulnerabilityID:  "CVE-2020-26116",
					InstalledVersion: "3.6.8-36.el8.alma",
					FixedVersion:     "3.6.8-37.el8.alma",
					Layer:            ftypes.Layer{},
				},
			},
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
				vs: alma.VulnSrc{},
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
		"alma8": {
			now:       time.Date(2021, 9, 9, 23, 59, 59, 0, time.UTC),
			osFamily:  "alma",
			osVersion: "8.4",
			expected:  true,
		},
		"alma8 with EOL": {
			now:       time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "alma",
			osVersion: "8.4",
			expected:  false,
		},
		"unknown": {
			now:       time.Date(2021, 9, 9, 23, 59, 59, 0, time.UTC),
			osFamily:  "alam",
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
