package alinux_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alinux"
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
			// ALINUX2-SA-2025:0006: postgresql security update (Important)
			// CVE-2024-10979: Incorrect control of environment variables in PostgreSQL PL/Perl
			name: "alinux 2",
			fixtures: []string{
				"testdata/fixtures/alinux.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "2.1903",
				pkgs: []ftypes.Package{
					{
						Name:    "postgresql",
						Version: "9.2.24",
						Release: "9.0.al7.2",
						Layer: ftypes.Layer{
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "postgresql",
					VulnerabilityID:  "CVE-2024-10979",
					InstalledVersion: "9.2.24-9.0.al7.2",
					FixedVersion:     "9.2.24-9.1.al7.2",
					Layer: ftypes.Layer{
						DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alinux,
						Name: "Alibaba Cloud Linux Security Center",
						URL:  "https://alas.aliyuncs.com/",
					},
				},
			},
		},
		{
			// ALINUX3-SA-2026:0021: glib2 security update (Moderate)
			// CVE-2025-13601: heap-based buffer overflow in g_escape_uri_string()
			name: "alinux 3",
			fixtures: []string{
				"testdata/fixtures/alinux.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3",
				pkgs: []ftypes.Package{
					{
						Name:    "glib2",
						Version: "2.68.4",
						Release: "14.al8",
						Layer: ftypes.Layer{
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "glib2",
					VulnerabilityID:  "CVE-2025-13601",
					InstalledVersion: "2.68.4-14.al8",
					FixedVersion:     "2.68.4-18.0.1.al8.1",
					Layer: ftypes.Layer{
						DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alinux,
						Name: "Alibaba Cloud Linux Security Center",
						URL:  "https://alas.aliyuncs.com/",
					},
				},
			},
		},
		{
			// ALINUX4-SA-2026:0034: python-urllib3 security update (Important)
			// CVE-2026-21441: urllib3 decompression bomb via HTTP redirect
			name: "alinux 4",
			fixtures: []string{
				"testdata/fixtures/alinux.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "4.0",
				pkgs: []ftypes.Package{
					{
						Name:    "python-urllib3",
						Version: "1.26.19",
						Release: "3.alnx4",
						Layer: ftypes.Layer{
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "python-urllib3",
					VulnerabilityID:  "CVE-2026-21441",
					InstalledVersion: "1.26.19-3.alnx4",
					FixedVersion:     "1.26.19-4.alnx4",
					Layer: ftypes.Layer{
						DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alinux,
						Name: "Alibaba Cloud Linux Security Center",
						URL:  "https://alas.aliyuncs.com/",
					},
				},
			},
		},
		{
			name: "no matching advisory",
			fixtures: []string{
				"testdata/fixtures/alinux.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3",
				pkgs: []ftypes.Package{
					{
						Name:    "bash",
						Version: "5.0.17",
						Release: "2.al8",
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
				osVer: "2",
				pkgs: []ftypes.Package{
					{
						Name:    "postgresql",
						Version: "9.2.24",
						Release: "9.0.al7.2",
					},
				},
			},
			wantErr: "failed to get Alinux advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := alinux.NewScanner()
			got, err := s.Detect(t.Context(), tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
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
			name: "alinux 2 before EOL",
			now:  time.Date(2023, 12, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "alinux",
				osVer:    "2.1903",
			},
			want: true,
		},
		{
			name: "alinux 2 after EOL",
			now:  time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "alinux",
				osVer:    "2",
			},
			want: false,
		},
		{
			name: "alinux 3 active",
			now:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "alinux",
				osVer:    "3",
			},
			want: true,
		},
		{
			name: "alinux 4 active",
			now:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "alinux",
				osVer:    "4.0",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), tt.now)
			s := alinux.NewScanner()
			got := s.IsSupportedVersion(ctx, tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
