package maven_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
)

func TestComparer_MatchVersion(t *testing.T) {
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
				currentVersion: "1.2.3-a1",
				constraint:     "<1.2.3",
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
			name: "version requirements",
			args: args{
				currentVersion: "1.2.3",
				constraint:     "(,1.2.3]",
			},
			want: true,
		},
		{
			name: "version soft requirements happy",
			args: args{
				currentVersion: "1.2.3",
				constraint:     "1.2.3",
			},
			want: true,
		},
		{
			name: "version soft requirements",
			args: args{
				currentVersion: "1.2.3",
				constraint:     "1.2.2",
			},
			want: false,
		},
		{
			name: "invalid constraint",
			args: args{
				currentVersion: "1.2.3",
				constraint:     `<1.0\.0`,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := maven.Comparer{}
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
