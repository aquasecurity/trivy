package version_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
)

func TestNewConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints string
		wantErr     bool
	}{
		{
			name:        "empty constraint returns error",
			constraints: "",
			wantErr:     true,
		},
		{
			name:        "single constraint with operator",
			constraints: ">=1.2.3",
			wantErr:     false,
		},
		{
			name:        "single constraint without operator",
			constraints: "1.2.3",
			wantErr:     false,
		},
		{
			name:        "multiple constraints with comma",
			constraints: ">=1.2.3, <2.0.0",
			wantErr:     false,
		},
		{
			name:        "multiple constraints with space",
			constraints: ">=1.2.3 <2.0.0",
			wantErr:     false,
		},
		{
			name:        "mixed operators",
			constraints: ">1.0.0, <=2.0.0, ==1.5.0",
			wantErr:     false,
		},
		{
			name:        "invalid constraint format",
			constraints: ">>>1.2.3",
			wantErr:     true,
		},
		{
			name:        "constraints with extra spaces",
			constraints: "  >=1.2.3  ,  <2.0.0  ",
			wantErr:     false,
		},
		{
			name:        "not equal operator",
			constraints: "!=1.2.3",
			wantErr:     false,
		},
		{
			name:        "equal operator variations",
			constraints: "=1.2.3, ==1.2.4",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := version.NewConstraints(tt.constraints, version.NewDEBComparer())
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestConstraints_Check(t *testing.T) {
	tests := []struct {
		name        string
		constraints string
		version     string
		want        bool
		wantErr     bool
	}{
		{
			name:        "empty version returns error",
			constraints: ">=1.2.3",
			version:     "",
			wantErr:     true,
		},
		{
			name:        "equal constraint satisfied",
			constraints: "1.2.3",
			version:     "1.2.3",
			want:        true,
		},
		{
			name:        "equal constraint not satisfied",
			constraints: "1.2.3",
			version:     "1.2.4",
			want:        false,
		},
		{
			name:        "greater than satisfied",
			constraints: ">1.2.3",
			version:     "1.2.4",
			want:        true,
		},
		{
			name:        "greater than not satisfied",
			constraints: ">1.2.3",
			version:     "1.2.3",
			want:        false,
		},
		{
			name:        "greater than not satisfied (lower)",
			constraints: ">1.2.3",
			version:     "1.2.2",
			want:        false,
		},
		{
			name:        "greater than or equal satisfied (equal)",
			constraints: ">=1.2.3",
			version:     "1.2.3",
			want:        true,
		},
		{
			name:        "greater than or equal satisfied (greater)",
			constraints: ">=1.2.3",
			version:     "1.2.4",
			want:        true,
		},
		{
			name:        "less than satisfied",
			constraints: "<2.0.0",
			version:     "1.9.9",
			want:        true,
		},
		{
			name:        "less than not satisfied",
			constraints: "<2.0.0",
			version:     "2.0.0",
			want:        false,
		},
		{
			name:        "less than or equal satisfied (equal)",
			constraints: "<=2.0.0",
			version:     "2.0.0",
			want:        true,
		},
		{
			name:        "less than or equal satisfied (less)",
			constraints: "<=2.0.0",
			version:     "1.9.9",
			want:        true,
		},
		{
			name:        "not equal satisfied",
			constraints: "!=1.2.3",
			version:     "1.2.4",
			want:        true,
		},
		{
			name:        "not equal not satisfied",
			constraints: "!=1.2.3",
			version:     "1.2.3",
			want:        false,
		},
		{
			name:        "multiple constraints AND logic (before first constraint)",
			constraints: ">=1.0.0, <2.0.0",
			version:     "0.9.0",
			want:        false,
		},
		{
			name:        "multiple constraints AND logic (after second constraint)",
			constraints: ">=1.0.0, <2.0.0",
			version:     "2.1.0",
			want:        false,
		},
		{
			name:        "multiple constraints AND logic (satisfied)",
			constraints: ">=1.0.0, <2.0.0",
			version:     "1.5.0",
			want:        true,
		},
		{
			name:        "range constraint (satisfied)",
			constraints: ">=1.2.3, <2.0.0",
			version:     "1.5.0",
			want:        true,
		},
		{
			name:        "multiple constraints with space separator",
			constraints: ">=1.2.3 <2.0.0",
			version:     "1.5.0",
			want:        true,
		},
		{
			name:        "debian version with revision",
			constraints: ">=1.2.3-1",
			version:     "1.2.3-2",
			want:        true,
		},
		{
			name:        "debian version with epoch",
			constraints: ">=1:1.2.3",
			version:     "1:1.2.4",
			want:        true,
		},
		{
			name:        "debian version with epoch and revision",
			constraints: ">=1:1.2.3-1",
			version:     "1:1.2.3-2",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := version.NewDEBComparer()
			constraints, err := version.NewConstraints(tt.constraints, comparer)
			require.NoError(t, err)

			got, err := constraints.Check(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConstraints_String(t *testing.T) {
	tests := []struct {
		name        string
		constraints string
		want        string
	}{
		{
			name:        "single constraint",
			constraints: ">=1.2.3",
			want:        ">=1.2.3",
		},
		{
			name:        "multiple constraints",
			constraints: ">=1.2.3, <2.0.0",
			want:        ">=1.2.3, <2.0.0",
		},
		{
			name:        "constraints with extra spaces",
			constraints: "  >=1.2.3  ,  <2.0.0  ",
			want:        ">=1.2.3, <2.0.0",
		},
		{
			name:        "space separated constraints",
			constraints: ">=1.2.3 <2.0.0",
			want:        ">=1.2.3, <2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := version.NewDEBComparer()
			constraints, err := version.NewConstraints(tt.constraints, comparer)
			require.NoError(t, err)

			got := constraints.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConstraints_CheckWithAPKComparer(t *testing.T) {
	tests := []struct {
		name        string
		constraints string
		version     string
		want        bool
	}{
		{
			name:        "alpine version comparison",
			constraints: ">=1.2.3-r0",
			version:     "1.2.3-r1",
			want:        true,
		},
		{
			name:        "alpine version with pre-release",
			constraints: "<1.2.3_pre1",
			version:     "1.2.2",
			want:        true,
		},
		{
			name:        "alpine version range",
			constraints: ">=1.2.3-r0, <2.0.0",
			version:     "1.5.0-r2",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := version.NewAPKComparer()
			constraints, err := version.NewConstraints(tt.constraints, comparer)
			require.NoError(t, err)

			got, err := constraints.Check(tt.version)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
