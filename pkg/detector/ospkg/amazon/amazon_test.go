package amazon_test

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
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/amazon"
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
			name: "amazon linux 1",
			fixtures: []string{
				"testdata/fixtures/amazon.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "1.2",
				pkgs: []ftypes.Package{
					{
						Name:    "bind",
						Epoch:   32,
						Version: "9.8.2",
						Release: "0.68.rc1.85.amzn1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bind",
					VulnerabilityID:  "CVE-2020-8625",
					InstalledVersion: "32:9.8.2-0.68.rc1.85.amzn1",
					FixedVersion:     "32:9.8.2-0.68.rc1.86.amzn1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Amazon,
						Name: "Amazon Linux Security Center",
						URL:  "https://alas.aws.amazon.com/",
					},
				},
			},
		},
		{
			name: "amazon linux 2",
			fixtures: []string{
				"testdata/fixtures/amazon.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "2",
				pkgs: []ftypes.Package{
					{
						Name:    "bash",
						Version: "4.2.45",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bash",
					VulnerabilityID:  "CVE-2019-9924",
					InstalledVersion: "4.2.45",
					FixedVersion:     "4.2.46-34.amzn2",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Amazon,
						Name: "Amazon Linux Security Center",
						URL:  "https://alas.aws.amazon.com/",
					},
				},
			},
		},
		{
			name: "amazon linux 2023",
			fixtures: []string{
				"testdata/fixtures/amazon.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "2023",
				pkgs: []ftypes.Package{
					{
						Name:    "protobuf",
						Version: "3.14.0-7.amzn2023.0.3",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "protobuf",
					VulnerabilityID:  "CVE-2022-1941",
					InstalledVersion: "3.14.0-7.amzn2023.0.3",
					FixedVersion:     "3.19.6-1.amzn2023.0.1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Amazon,
						Name: "Amazon Linux Security Center",
						URL:  "https://alas.aws.amazon.com/",
					},
				},
			},
		},
		{
			name: "empty version",
			fixtures: []string{
				"testdata/fixtures/amazon.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "2",
				pkgs: []ftypes.Package{
					{
						Name: "bash",
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
				osVer: "1",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			wantErr: "failed to get amazon advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := amazon.NewScanner()
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
			name: "amazon linux 1",
			now:  time.Date(2022, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "amazon",
				osVer:    "1",
			},
			want: true,
		},
		{
			name: "amazon linux 1 EOL",
			now:  time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "amazon",
				osVer:    "1",
			},
			want: false,
		},
		{
			name: "amazon linux 2",
			now:  time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "amazon",
				osVer:    "2",
			},
			want: true,
		},
		{
			name: "amazon linux 2022",
			now:  time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "amazon",
				osVer:    "2022",
			},
			want: false,
		},
		{
			name: "amazon linux 2023",
			now:  time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "amazon",
				osVer:    "2023",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := amazon.NewScanner(amazon.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
