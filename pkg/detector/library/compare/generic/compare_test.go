package generic_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/generic"
)

func TestGenericComparer_MatchVersion(t *testing.T) {
	type args struct {
		ver        string
		constraint string
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
				ver:        "1.2.2-alpha",
				constraint: "<=1.2.2",
			},
			want: true,
		},
		{
			name: "multiple constraints",
			args: args{
				ver:        "2.0.0",
				constraint: ">=1.7.0 <1.7.16 || >=1.8.0 <1.8.8 || >=2.0.0 <2.0.8 || >=3.0.0-beta.1 <3.0.0-beta.7",
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				ver:        "1.2..4",
				constraint: "<1.0.0",
			},
			wantErr: true,
		},
		{
			name: "improper constraint",
			args: args{
				ver:        "1.2.3",
				constraint: "*",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := generic.Comparer{}
			got, err := v.MatchVersion(tt.args.ver, tt.args.constraint)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
