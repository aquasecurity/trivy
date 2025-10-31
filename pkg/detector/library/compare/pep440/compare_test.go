package pep440_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

func TestPep440Comparer_MatchVersion(t *testing.T) {
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
			name: "pre-release",
			args: args{
				currentVersion: "1.2.3a1",
				constraint:     ">=1.2.2",
			},
			want: true,
		},
		{
			name: "multiple constraints",
			args: args{
				currentVersion: "2.0.0",
				constraint:     ">=1.7.0 <1.7.16 || >=1.8.0 <1.8.8 || >=2.0.0 <2.0.8 || >=3.0.0b1 <3.0.0b7",
			},
			want: true,
		},
		{
			name: "exact versions",
			args: args{
				currentVersion: "2.1.0.post1",
				constraint:     "2.1.0.post1 || 2.0.0",
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
			c := pep440.Comparer{}
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
