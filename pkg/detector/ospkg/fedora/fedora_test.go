package fedora_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/fedora"
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
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/fedora.yaml"},
			args: args{
				osVer: "35",
				pkgs: []ftypes.Package{
					{
						Name:            "vim-minimal",
						Epoch:           2,
						Version:         "8.2.3642",
						Release:         "1.fc35",
						Arch:            "x86_64",
						SrcName:         "vim",
						SrcEpoch:        2,
						SrcVersion:      "8.2.3642",
						SrcRelease:      "1.fc35",
						Modularitylabel: "",
						License:         "Vim and MIT",
						Layer:           ftypes.Layer{},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "vim-minimal",
					VulnerabilityID:  "CVE-2022-0158",
					InstalledVersion: "2:8.2.3642-1.fc35",
					FixedVersion:     "2:8.2.4068-1.fc35",
					Layer:            ftypes.Layer{},
				},
			},
		},
		{
			name:     "Get returns an error",
			fixtures: []string{"testdata/fixtures/invalid.yaml"},
			args: args{
				osVer: "35",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.5-12",
						SrcName:    "jq",
						SrcVersion: "1.5-12",
					},
				},
			},
			wantErr: "failed to get Fedora advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := fedora.NewScanner()
			got, err := s.Detect(tt.args.osVer, tt.args.pkgs)
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
		osFamily string
		osVer    string
	}
	tests := []struct {
		name string
		now  time.Time
		args args
		want bool
	}{
		{
			name: "fedora 35",
			now:  time.Date(2019, 3, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "fedora",
				osVer:    "35",
			},
			want: true,
		},
		{
			name: "fedora 35 with EOL",
			now:  time.Date(2022, 12, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "rocky",
				osVer:    "35",
			},
			want: false,
		},
		{
			name: "unknown",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "fedora",
				osVer:    "unknown",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fedora.NewScanner(fedora.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
