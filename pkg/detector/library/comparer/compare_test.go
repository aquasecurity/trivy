package comparer_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionComparer_MatchVersion(t *testing.T) {
	type args struct {
		currentVersion string
		constraints    string
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
				constraints:    ">1.2.0",
			},
			want: true,
		},
		{
			name: "pre-release",
			args: args{
				currentVersion: "1.2.3-alpha",
				constraints:    ">1.2.3",
			},
			want: false,
		},
		{
			name: "build metadata",
			args: args{
				currentVersion: "1.2.3+alpha",
				constraints:    "< 1.0.0 || >=1.2.3",
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				currentVersion: "1.2..4",
				constraints:    ">1.2.0",
			},
			wantErr: "malformed version",
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.4",
				constraints:    "!1.2.0",
			},
			wantErr: "improper constraint",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := comparer.GenericComparer{}
			got, err := r.MatchVersion(tt.args.currentVersion, tt.args.constraints)
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
