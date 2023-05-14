package unpackaged_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler/unpackaged"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rekortest"
)

func Test_unpackagedHook_Handle(t *testing.T) {
	type args struct {
		res  *analyzer.AnalysisResult
		blob *types.BlobInfo
	}
	tests := []struct {
		name    string
		args    args
		want    *types.BlobInfo
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				res: &analyzer.AnalysisResult{
					Digests: map[string]string{
						"go.mod": "sha256:23f4e10c43c7654e33a3c9570913c8c9c528292762f1a5c4a97253e9e4e4b238",
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/spf13/cobra",
								Version: "1.5.0",
								Ref:     "pkg:golang/github.com/spf13/cobra@1.5.0",
							},
						},
					},
				},
			},
		},
		{
			name: "404",
			args: args{
				res: &analyzer.AnalysisResult{
					Digests: map[string]string{
						"go.mod": "sha256:unknown",
					},
				},
			},
			wantErr: "failed to search",
		},
	}

	require.NoError(t, log.InitLogger(false, true))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := rekortest.NewServer(t)
			defer ts.Close()

			// Set the testing URL
			opt := artifact.Option{
				RekorURL: ts.URL(),
			}

			got := &types.BlobInfo{}
			h, err := unpackaged.NewUnpackagedHandler(opt)
			require.NoError(t, err)

			err = h.Handle(context.Background(), tt.args.res, got)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}
