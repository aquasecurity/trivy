package language_test

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type mockParser struct {
	t *testing.T
}

func (p *mockParser) Parse(r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	b, err := io.ReadAll(r)
	require.NoError(p.t, err)

	switch string(b) {
	case "happy":
		return []types.Package{
			{
				Name:    "test",
				Version: "1.2.3",
			},
		}, nil, nil
	case "sad":
		return nil, nil, xerrors.New("unexpected error")
	}

	return nil, nil, nil
}

func TestAnalyze(t *testing.T) {
	type args struct {
		fileType types.LangType
		filePath string
		content  xio.ReadSeekerAt
	}
	tests := []struct {
		name    string
		args    args
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				fileType: types.GoBinary,
				filePath: "app/myweb",
				content:  strings.NewReader("happy"),
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "app/myweb",
						Packages: types.Packages{
							{
								Name:    "test",
								Version: "1.2.3",
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			args: args{
				fileType: types.GoBinary,
				filePath: "app/myweb",
				content:  strings.NewReader(""),
			},
			want: nil,
		},
		{
			name: "sad path",
			args: args{
				fileType: types.Jar,
				filePath: "app/myweb",
				content:  strings.NewReader("sad"),
			},
			wantErr: "unexpected error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &mockParser{t: t}

			got, err := language.Analyze(tt.args.fileType, tt.args.filePath, tt.args.content, mp)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
