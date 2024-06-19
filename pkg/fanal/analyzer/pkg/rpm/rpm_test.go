package rpm

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type mockRPMDB struct {
	packages []*rpmdb.PackageInfo
	err      error
}

func (m *mockRPMDB) ListPackages() ([]*rpmdb.PackageInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.packages, nil
}

func Test_rpmPkgAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.AnalysisInput
		want    int
		wantErr string
	}{
		{
			name: "valid",
			input: analyzer.AnalysisInput{
				FilePath: "testdata/valid",
				Content:  lo.Must(os.Open("testdata/valid")),
			},
			want: 1,
		},
		{
			name: "broken",
			input: analyzer.AnalysisInput{
				FilePath: "testdata/valid",
				Content:  strings.NewReader("broken"),
			},
			want:    0,
			wantErr: "unexpected EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := rpmPkgAnalyzer{}
			got, err := a.Analyze(context.Background(), tt.input)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got.PackageInfos, tt.want)
		})
	}
}

func Test_splitFileName(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantName string
		wantVer  string
		wantRel  string
		wantErr  bool
	}{
		{
			name:     "valid name",
			filename: "glibc-2.17-307.el7.1.src.rpm",
			wantName: "glibc",
			wantVer:  "2.17",
			wantRel:  "307.el7.1",
			wantErr:  false,
		},
		{
			name:     "invalid name",
			filename: "elasticsearch-5.6.16-1-src.rpm",
			wantName: "",
			wantVer:  "",
			wantRel:  "",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVer, gotRel, err := splitFileName(tt.filename)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantVer, gotVer)
			assert.Equal(t, tt.wantRel, gotRel)
		})
	}
}

func Test_rpmPkgAnalyzer_listPkgs(t *testing.T) {
	type mock struct {
		packages []*rpmdb.PackageInfo
		err      error
	}
	tests := []struct {
		name      string
		mock      mock
		wantPkgs  types.Packages
		wantFiles []string
		wantErr   string
	}{
		{
			name: "normal",
			mock: mock{
				packages: []*rpmdb.PackageInfo{
					{
						Name:      "glibc",
						Version:   "2.17",
						Release:   "307.el7.1",
						Arch:      "x86_64",
						SourceRpm: "glibc-2.17-317.el7.src.rpm",
						DirNames: []string{
							"/etc",
							"/lib64",
						},
						DirIndexes: []int32{
							0,
							0,
							1,
						},
						BaseNames: []string{
							"ld.so.conf",
							"rpc",
							"libm-2.27.so",
						},
						Vendor: "Red Hat",
					},
				},
			},
			wantPkgs: types.Packages{
				{
					ID:         "glibc@2.17-307.el7.1.x86_64",
					Name:       "glibc",
					Version:    "2.17",
					Release:    "307.el7.1",
					Arch:       "x86_64",
					SrcName:    "glibc",
					SrcVersion: "2.17",
					SrcRelease: "317.el7",
					Maintainer: "Red Hat",
					InstalledFiles: []string{
						"/etc/ld.so.conf",
						"/etc/rpc",
						"/lib64/libm-2.27.so",
					},
				},
			},
			wantFiles: []string{
				"/etc/ld.so.conf",
				"/etc/rpc",
				"/lib64/libm-2.27.so",
			},
		},
		{
			name: "Amazon official package without `Vendor` field",
			mock: mock{
				packages: []*rpmdb.PackageInfo{
					{
						Name:      "curl-minimal",
						Version:   "8.3.0",
						Release:   "1.amzn2023.0.2",
						Arch:      "aarch64",
						SourceRpm: "curl-8.3.0-1.amzn2023.0.2.src.rpm",
						DirNames: []string{
							"/usr/bin/",
							"/usr/lib/",
							"/usr/lib/.build-id/",
							"/usr/lib/.build-id/aa/",
							"/usr/share/man/man1/",
						},
						DirIndexes: []int32{
							0,
							1,
							2,
							3,
							4,
						},
						BaseNames: []string{
							"curl",
							".build-id",
							"aa",
							"d987ea9bc1c73706d12c7a143ee792117851ff",
							"curl.1.gz",
						},
						Vendor: "",
					},
				},
			},
			wantPkgs: types.Packages{
				{
					ID:         "curl-minimal@8.3.0-1.amzn2023.0.2.aarch64",
					Name:       "curl-minimal",
					Version:    "8.3.0",
					Release:    "1.amzn2023.0.2",
					Arch:       "aarch64",
					SrcName:    "curl",
					SrcVersion: "8.3.0",
					SrcRelease: "1.amzn2023.0.2",
					InstalledFiles: []string{
						"/usr/bin/curl",
						"/usr/lib/.build-id",
						"/usr/lib/.build-id/aa",
						"/usr/lib/.build-id/aa/d987ea9bc1c73706d12c7a143ee792117851ff",
						"/usr/share/man/man1/curl.1.gz",
					},
				},
			},
			wantFiles: []string{
				"/usr/bin/curl",
				"/usr/lib/.build-id",
				"/usr/lib/.build-id/aa",
				"/usr/lib/.build-id/aa/d987ea9bc1c73706d12c7a143ee792117851ff",
				"/usr/share/man/man1/curl.1.gz",
			},
		},
		{
			name: "invalid source rpm",
			mock: mock{
				packages: []*rpmdb.PackageInfo{
					{
						Name:      "glibc",
						Version:   "2.17",
						Release:   "307.el7.1",
						Arch:      "x86_64",
						SourceRpm: "invalid",
					},
				},
			},
			wantPkgs: types.Packages{
				{
					ID:      "glibc@2.17-307.el7.1.x86_64",
					Name:    "glibc",
					Version: "2.17",
					Release: "307.el7.1",
					Arch:    "x86_64",
				},
			},
		},
		{
			name: "sad path",
			mock: mock{
				err: errors.New("unexpected error"),
			},
			wantErr: "unexpected error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockRPMDB{
				packages: tt.mock.packages,
				err:      tt.mock.err,
			}

			a := newRPMPkgAnalyzer()
			gotPkgs, gotFiles, err := a.listPkgs(context.Background(), m)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantFiles, gotFiles)
		})
	}
}
