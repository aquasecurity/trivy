package bitnami_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
)

func TestBitnamiComparer_MatchVersion(t *testing.T) {
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
			name: "not vulnerable constraint",
			args: args{
				currentVersion: "1.2.3",
				constraint:     "<1.2.3",
			},
			want: false,
		},
		{
			name: "vulnerable constraint",
			args: args{
				currentVersion: "1.2.3",
				constraint:     "<=1.2.3",
			},
			want: true,
		},
		{
			name: "revision on current version patched",
			args: args{
				currentVersion: "1.2.3-1",
				constraint:     ">=1.2.3",
			},
			want: true,
		},
		{
			name: "revision on current version not patched",
			args: args{
				currentVersion: "1.2.3-1",
				constraint:     ">=1.2.4",
			},
			want: false,
		},
		{
			name: "revision on patch",
			args: args{
				currentVersion: "1.2.4",
				constraint:     ">=1.2.3-1",
			},
			want: true,
		},
		{
			name: "vulnerable with revision on patch",
			args: args{
				currentVersion: "1.2.3",
				constraint:     ">=1.2.3-1",
			},
			want: false,
		},
		{
			name: "revisions on both current and patch",
			args: args{
				currentVersion: "1.2.4-2",
				constraint:     ">=1.2.3-1",
			},
			want: true,
		},
		{
			name: "revision on both current and patch vulnerable",
			args: args{
				currentVersion: "1.2.3-0",
				constraint:     ">=1.2.3-1",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bitnami.Comparer{}
			got, err := b.MatchVersion(tt.args.currentVersion, tt.args.constraint)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
