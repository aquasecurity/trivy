package binary

import (
	"os"
	"runtime"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gobinaryLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/executable_gobinary",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "testdata/executable_gobinary",
						Packages: types.Packages{
							{
								ID:           "github.com/aquasecurity/test",
								Name:         "github.com/aquasecurity/test",
								Version:      "",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
									"github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
									"stdlib@v1.15.2",
								},
							},
							{
								ID:           "stdlib@v1.15.2",
								Name:         "stdlib",
								Version:      "v1.15.2",
								Relationship: types.RelationshipDirect,
							},
							{
								ID:      "github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46",
								Name:    "github.com/aquasecurity/go-pep440-version",
								Version: "v0.0.0-20210121094942-22b2f8951d46",
								Digests: []digest.SourcedDigest{
									{
										Digest: "sha256:be65cd97e1c37eaa9782bd2e6355202b5180869b3c9db000b6a1cd05c8327fee",
										Source: digest.SourceGoModuleH1,
									},
								},
							},
							{
								ID:      "github.com/aquasecurity/go-version@v0.0.0-20210121072130-637058cfe492",
								Name:    "github.com/aquasecurity/go-version",
								Version: "v0.0.0-20210121072130-637058cfe492",
								Digests: []digest.SourcedDigest{
									{
										Digest: "sha256:adc106e47238f74145d1aef3bafc4ec5e9f9d9d7728027cd5633f45ce08c97e3",
										Source: digest.SourceGoModuleH1,
									},
								},
							},
							{
								ID:      "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:    "golang.org/x/xerrors",
								Version: "v0.0.0-20200804184101-5ec99f83aff1",
								Digests: []digest.SourcedDigest{
									{
										Digest: "sha256:828d5b2bf0ff045655d88f1c21077534a119fb4a304931b57c34dc8b822a15c1",
										Source: digest.SourceGoModuleH1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "not go binary",
			inputFile: "testdata/executable_bash",
		},
		{
			name:      "broken elf",
			inputFile: "testdata/broken_elf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := gobinaryLibraryAnalyzer{}
			ctx := t.Context()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gobinaryLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "executable file",
			filePath: lo.Ternary(runtime.GOOS == "windows", "testdata/binary.exe", "testdata/0755"),
			want:     true,
		},
		{
			name:     "file perm 0644",
			filePath: "testdata/0644",
			want:     false,
		},
		{
			name:     "symlink",
			filePath: "testdata/symlink",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gobinaryLibraryAnalyzer{}
			fileInfo, err := os.Lstat(tt.filePath)
			require.NoError(t, err)
			got := a.Required(tt.filePath, fileInfo)
			assert.Equal(t, tt.want, got, fileInfo.Mode().Perm())
		})
	}
}
