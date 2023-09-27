package rocky_test

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
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rocky"
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
				"testdata/fixtures/rocky.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.5",
				pkgs: []ftypes.Package{
					{
						Name:            "bpftool",
						Epoch:           0,
						Version:         "4.18.0",
						Release:         "348.el8.0.3",
						Arch:            "aarch64",
						SrcName:         "kernel",
						SrcEpoch:        0,
						SrcVersion:      "4.18.0",
						SrcRelease:      "348.el8.0.3",
						Modularitylabel: "",
						Licenses:        []string{"GPLv2"},
						Layer:           ftypes.Layer{},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bpftool",
					VulnerabilityID:  "CVE-2021-20317",
					InstalledVersion: "4.18.0-348.el8.0.3",
					FixedVersion:     "5.18.0-348.2.1.el8_5",
					Layer:            ftypes.Layer{},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
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
				osVer: "8.5",
				pkgs: []ftypes.Package{
					{
						Name:            "nginx",
						Epoch:           1,
						Version:         "1.16.1",
						Release:         "2.module+el8.4.0+543+efbf198b.0",
						Arch:            "x86_64",
						SrcName:         "nginx",
						SrcEpoch:        1,
						SrcVersion:      "1.16.1",
						SrcRelease:      "2.module+el8.4.0+543+efbf198b.0",
						Modularitylabel: "nginx:1.16:8040020210610090125:9f9e2e7e",
						Licenses:        []string{"BSD"},
						Layer:           ftypes.Layer{},
					},
				},
			},
			want: nil,
		},
		{
			name: "Get returns an error",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.5",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.5-12",
						SrcName:    "jq",
						SrcVersion: "1.5-12",
					},
				},
			},
			wantErr: "failed to get Rocky Linux advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := rocky.NewScanner()
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
			name: "rocky 8.5",
			now:  time.Date(2019, 3, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "rocky",
				osVer:    "8.5",
			},
			want: true,
		},
		{
			name: "rocky 8.5 with EOL",
			now:  time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "rocky",
				osVer:    "8.5",
			},
			want: false,
		},
		{
			name: "unknown",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "rocky",
				osVer:    "unknown",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := rocky.NewScanner(rocky.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
