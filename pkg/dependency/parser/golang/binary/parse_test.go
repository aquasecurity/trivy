package binary_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	wantPkgs := []ftypes.Package{
		{
			ID:           "github.com/aquasecurity/test",
			Name:         "github.com/aquasecurity/test",
			Version:      "",
			Relationship: ftypes.RelationshipRoot,
		},
		{
			ID:           "stdlib@v1.15.2",
			Name:         "stdlib",
			Version:      "v1.15.2",
			Relationship: ftypes.RelationshipDirect,
		},
		{
			ID:      "github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
			Name:    "github.com/aquasecurity/go-pep440-version",
			Version: "v0.0.0-20210121094942-22b2f8951d46",
		},
		{
			ID:      "github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
			Name:    "github.com/aquasecurity/go-version",
			Version: "v0.0.0-20210121072130-637058cfe492",
		},
		{
			ID:      "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
			Name:    "golang.org/x/xerrors",
			Version: "v0.0.0-20200804184101-5ec99f83aff1",
		},
	}
	wantDeps := []ftypes.Dependency{
		{
			ID: "github.com/aquasecurity/test",
			DependsOn: []string{
				"github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
				"github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
				"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
				"stdlib@v1.15.2",
			},
		},
	}

	tests := []struct {
		name      string
		inputFile string
		wantPkgs  []ftypes.Package
		wantDeps  []ftypes.Dependency
		wantErr   string
	}{
		{
			name:      "ELF",
			inputFile: "testdata/test.elf",
			wantPkgs:  wantPkgs,
			wantDeps:  wantDeps,
		},
		{
			name:      "PE",
			inputFile: "testdata/test.exe",
			wantPkgs:  wantPkgs,
			wantDeps:  wantDeps,
		},
		{
			name:      "Mach-O",
			inputFile: "testdata/test.macho",
			wantPkgs:  wantPkgs,
			wantDeps:  wantDeps,
		},
		{
			name:      "with replace directive",
			inputFile: "testdata/replace.elf",
			wantPkgs: []ftypes.Package{
				{
					ID:           "github.com/ebati/trivy-mod-parse",
					Name:         "github.com/ebati/trivy-mod-parse",
					Version:      "",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "stdlib@v1.16.4",
					Name:         "stdlib",
					Version:      "v1.16.4",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:      "github.com/davecgh/go-spew@v1.1.1",
					Name:    "github.com/davecgh/go-spew",
					Version: "v1.1.1",
				},
				{
					ID:      "github.com/go-sql-driver/mysql@v1.5.0",
					Name:    "github.com/go-sql-driver/mysql",
					Version: "v1.5.0",
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "github.com/ebati/trivy-mod-parse",
					DependsOn: []string{
						"github.com/davecgh/go-spew@v1.1.1",
						"github.com/go-sql-driver/mysql@v1.5.0",
						"stdlib@v1.16.4",
					},
				},
			},
		},
		{
			name:      "with semver main module version",
			inputFile: "testdata/semver-main-module-version.macho",
			wantPkgs: []ftypes.Package{
				{
					ID:           "go.etcd.io/bbolt@v1.3.5",
					Name:         "go.etcd.io/bbolt",
					Version:      "v1.3.5",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "stdlib@v1.20.6",
					Name:         "stdlib",
					Version:      "v1.20.6",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "go.etcd.io/bbolt@v1.3.5",
					DependsOn: []string{
						"stdlib@v1.20.6",
					},
				},
			},
		},
		{
			name:      "with -ldflags=\"-X main.version=v1.0.0\"",
			inputFile: "testdata/main-version-via-ldflags.elf",
			wantPkgs: []ftypes.Package{
				{
					ID:           "github.com/aquasecurity/test@v1.0.0",
					Name:         "github.com/aquasecurity/test",
					Version:      "v1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "stdlib@v1.22.1",
					Name:         "stdlib",
					Version:      "v1.22.1",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "github.com/aquasecurity/test@v1.0.0",
					DependsOn: []string{
						"stdlib@v1.22.1",
					},
				},
			},
		},
		{
			name:      "goexperiment",
			inputFile: "testdata/goexperiment",
			wantPkgs: []ftypes.Package{
				{
					ID:           "stdlib@v1.22.1",
					Name:         "stdlib",
					Version:      "v1.22.1",
					Relationship: ftypes.RelationshipDirect,
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/dummy",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, gotDeps, err := binary.NewParser().Parse(f)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}

func TestParser_ParseLDFlags(t *testing.T) {
	type args struct {
		name  string
		flags []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "with version suffix",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version/app.ver=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with version suffix titlecased",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.Version=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with ver suffix",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version/app.ver=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with ver suffix titlecased",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.Ver=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with double quoted flag",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X=\"github.com/aquasecurity/trivy/pkg/version.Ver=0.50.1\"",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with semver version without v prefix",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.Ver=0.50.1'",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with `cmd` + `default prefix` flags",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/cmd/Any.Ver=0.50.0'",
					"-X='github.com/aquasecurity/trivy/pkg/version.Ver=0.50.1'",
				},
			},
			want: "0.50.0",
		},
		{
			name: "with `cmd` flag",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/cmd/Any.Ver=0.50.0'",
				},
			},
			want: "0.50.0",
		},
		{
			name: "with `cmd` + `other` flags",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/cmd/Any.Ver=0.50.0'",
					"-X='github.com/aquasecurity/trivy/pkg/Any.Ver=0.50.1'",
				},
			},
			want: "0.50.0",
		},
		{
			name: "with `default prefix` flag",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/pkg/Common.Ver=0.50.1'",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with `default prefix` + `other` flags",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/pkg/Any.Ver=0.50.0'",
					"-X='github.com/aquasecurity/trivy/pkg/Common.Ver=0.50.1'",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with `other` flag",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/pkg/Any.Ver=0.50.1'",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with 2 flags using default prefixes",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/pkg/Common.Ver=0.50.0'",
					"-X='github.com/aquasecurity/trivy/pkg/Main.Ver=0.50.1'",
				},
			},
			want: "",
		},
		{
			name: "with two `other` flags",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-X='github.com/aquasecurity/trivy/pkg/Any.Ver=0.50.1'",
					"-X='github.com/aquasecurity/trivy/pkg/Any-pref.Ver=0.50.0'",
				},
			},
			want: "",
		},
		{
			name: "with version with extra prefix",
			args: args{
				name: "github.com/argoproj/argo-cd/v2",
				flags: []string{
					"-s",
					"-w",
					"-X='github.com/argoproj/argo-cd/v2/common.kubectlVersion=v0.26.11'",
				},
			},
			want: "",
		},
		{
			name: "with no flags",
			args: args{
				name:  "github.com/aquasecurity/test",
				flags: []string{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := binary.NewParser()
			require.Equal(t, tt.want, p.ParseLDFlags(tt.args.name, tt.args.flags))
		})
	}
}
