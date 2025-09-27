package saas

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsLoggedIn(t *testing.T) {
	tests := []struct {
		name   string
		config *CloudConfig
		want   bool
	}{
		{
			name:   "logged in",
			config: &CloudConfig{Token: "testtoken"},
			want:   true,
		},
		{
			name:   "not logged in",
			config: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		isLoggedIn = false
		cloudConfig = nil

		t.Run(tt.name, func(t *testing.T) {
			isLoggedIn = false
			setGlobalCloudConfig(tt.config)
			require.Equal(t, tt.want, IsLoggedIn())
		})
	}

}
