package alma_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alma"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/alma.yaml",
				"testdata/fixtures/data-source.yaml",
			},
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
						Licenses:        []string{"Python"},
						Layer:           ftypes.Layer{},
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
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alma,
						Name: "AlmaLinux Product Errata",
						URL:  "https://errata.almalinux.org/",
					},
				},
			},
		},
		{
			name: "skip modular package",
			fixtures: []string{
				"testdata/fixtures/modular.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.4",
				pkgs: []ftypes.Package{
					{
						Name:            "nginx",
						Epoch:           1,
						Version:         "1.14.1",
						Release:         "8.module_el8.3.0+2165+af250afe.alma",
						Arch:            "x86_64",
						SrcName:         "nginx",
						SrcEpoch:        1,
						SrcVersion:      "1.14.1",
						SrcRelease:      "8.module_el8.3.0+2165+af250afe.alma",
						Modularitylabel: "", // ref: https://bugs.almalinux.org/view.php?id=173 ,  https://github.com/aquasecurity/trivy/issues/2342#issuecomment-1158459628
						Licenses:        []string{"BSD"},
						Layer:           ftypes.Layer{},
					},
				},
			},
			want: nil,
		},
		{
			name: "modular package",
			fixtures: []string{
				"testdata/fixtures/modular.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.6",
				pkgs: []ftypes.Package{
					{
						Name:            "httpd",
						Epoch:           0,
						Version:         "2.4.37",
						Release:         "46.module_el8.6.0+2872+fe0ff7aa.1.alma",
						Arch:            "x86_64",
						SrcName:         "httpd",
						SrcEpoch:        0,
						SrcVersion:      "2.4.37",
						SrcRelease:      "46.module_el8.6.0+2872+fe0ff7aa.1.alma",
						Modularitylabel: "httpd:2.4:8060020220510105858:9edba152",
						Licenses:        []string{"ASL 2.0"},
						Layer:           ftypes.Layer{},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "httpd",
					VulnerabilityID:  "CVE-2020-35452",
					InstalledVersion: "2.4.37-46.module_el8.6.0+2872+fe0ff7aa.1.alma",
					FixedVersion:     "2.4.37-47.module_el8.6.0+2872+fe0ff7aa.1.alma",
					Layer:            ftypes.Layer{},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alma,
						Name: "AlmaLinux Product Errata",
						URL:  "https://errata.almalinux.org/",
					},
				},
			},
		},
		{
			name: "Get returns an error",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.4",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.5-12",
						SrcName:    "jq",
						SrcVersion: "1.5-12",
					},
				},
			},
			wantErr: "failed to get AlmaLinux advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := alma.NewScanner()
			got, err := s.Detect(tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	type args struct {
		osFamily ftypes.OSType
		osVer    string
	}
	tests := []struct {
		name string
		now  time.Time
		args args
		want bool
	}{
		{
			name: "alma 8.4",
			now:  time.Date(2019, 3, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alma",
				osVer:    "8.4",
			},
			want: true,
		},
		{
			name: "alma 8.4 with EOL",
			now:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "alma",
				osVer:    "8.4",
			},
			want: false,
		},
		{
			name: "unknown",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alma",
				osVer:    "unknown",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := alma.NewScanner(alma.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
