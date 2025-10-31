package npm_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
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
		wantErr bool
	}{
		{
			name: "x range",
			args: args{
				currentVersion: "2.0.1",
				constraint:     "2.0.x || 2.1.x",
			},
			want: true,
		},
		{
			name: "exact versions",
			args: args{
				currentVersion: "2.1.0-M1",
				constraint:     "2.1.0-M1 || 2.1.0-M2",
			},
			want: true,
		},
		{
			name: "caret",
			args: args{
				currentVersion: "2.0.18",
				constraint:     "^2.0.18 || ^3.0.16",
			},
			want: true,
		},
		{
			name: "multiple constraints",
			args: args{
				currentVersion: "2.0.0",
				constraint:     ">=1.7.0 <1.7.16 || >=1.8.0 <1.8.8 || >=2.0.0 <2.0.8 || >=3.0.0-beta.1 <3.0.0-beta.7",
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				currentVersion: "1.2..4",
				constraint:     "<1.0.0",
			},
			wantErr: true,
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.4",
				constraint:     "!1.0.0",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := npm.Comparer{}
			got, err := c.MatchVersion(tt.args.currentVersion, tt.args.constraint)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
