package version_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
)

func TestDEBComparer_Compare(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		want     int
		wantErr  bool
	}{
		{
			name:     "equal versions",
			version1: "1.2.3",
			version2: "1.2.3",
			want:     0,
		},
		{
			name:     "version1 greater",
			version1: "1.2.4",
			version2: "1.2.3",
			want:     1,
		},
		{
			name:     "version1 less",
			version1: "1.2.2",
			version2: "1.2.3",
			want:     -1,
		},
		{
			name:     "with debian revision - equal base, different revision",
			version1: "1.2.3-1",
			version2: "1.2.3-2",
			want:     -1,
		},
		{
			name:     "with epoch - different epoch",
			version1: "1:1.2.3",
			version2: "2:1.2.3",
			want:     -1,
		},
		{
			name:     "with epoch and revision",
			version1: "1:1.2.3-1",
			version2: "1:1.2.3-2",
			want:     -1,
		},
		{
			name:     "ubuntu specific version",
			version1: "1.2.3-1ubuntu1",
			version2: "1.2.3-1ubuntu2",
			want:     -1,
		},
		{
			name:     "invalid version1",
			version1: "invalid_version",
			version2: "1.2.3",
			wantErr:  true,
		},
		{
			name:     "invalid version2",
			version1: "1.2.3",
			version2: "invalid_version",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := version.NewDEBComparer()
			got, err := c.Compare(tt.version1, tt.version2)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAPKComparer_Compare(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		want     int
		wantErr  bool
	}{
		{
			name:     "equal versions",
			version1: "1.2.3",
			version2: "1.2.3",
			want:     0,
		},
		{
			name:     "version1 greater",
			version1: "1.2.4",
			version2: "1.2.3",
			want:     1,
		},
		{
			name:     "version1 less",
			version1: "1.2.2",
			version2: "1.2.3",
			want:     -1,
		},
		{
			name:     "with alpine revision - equal base, different revision",
			version1: "1.2.3-r0",
			version2: "1.2.3-r1",
			want:     -1,
		},
		{
			name:     "pre-release versions",
			version1: "1.2.3_pre1",
			version2: "1.2.3",
			want:     -1,
		},
		{
			name:     "complex alpine version",
			version1: "1.2.3-r0",
			version2: "1.2.3_pre1-r0",
			want:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := version.NewAPKComparer()
			got, err := c.Compare(tt.version1, tt.version2)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
