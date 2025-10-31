package rubygems_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
)

func TestRubyGemsComparer_MatchVersion(t *testing.T) {
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
			name: "pre-release without dot",
			args: args{
				currentVersion: "4.1a",
				constraint:     "< 4.2b1",
			},
			want: true,
		},
		{
			// https://github.com/aquasecurity/trivy/issues/108
			name: "hyphen",
			args: args{
				currentVersion: "1.9.25-x86-mingw32",
				constraint:     ">=1.9.24",
			},
			want: true,
		},
		{
			// https://github.com/aquasecurity/trivy/issues/108
			name: "pessimistic",
			args: args{
				currentVersion: "1.8.6-java",
				constraint:     "~> 1.5.5 || ~> 1.6.8 || >= 1.7.7",
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				currentVersion: "1.2..4",
				constraint:     ">=1.2.3",
			},
			wantErr: true,
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.4",
				constraint:     "!1.2.0",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := rubygems.Comparer{}
			got, err := r.MatchVersion(tt.args.currentVersion, tt.args.constraint)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
