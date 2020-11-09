package node_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/detector/library/node"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmComparer_MatchVersion(t *testing.T) {
	type args struct {
		currentVersion string
		constraint     string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				currentVersion: "1.2.3",
				constraint:     ">1.2.0",
			},
			want: true,
		},
		{
			name: "pre-release",
			args: args{
				currentVersion: "1.2.3-alpha",
				constraint:     ">1.2.3",
			},
			want: false,
		},
		{
			name: "caret",
			args: args{
				currentVersion: "1.2.3",
				constraint:     "^1.2.0",
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				currentVersion: "1.2..4",
				constraint:     ">1.2.0",
			},
			wantErr: "invalid semantic version",
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.4",
				constraint:     "!1.2.0",
			},
			wantErr: "improper constraint",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := node.NpmComparer{}
			got, err := r.MatchVersion(tt.args.currentVersion, tt.args.constraint)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
