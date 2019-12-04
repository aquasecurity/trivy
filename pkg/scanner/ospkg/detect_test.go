package ospkg

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/rpc/client/ospkg"

	"github.com/stretchr/testify/assert"
)

func TestNewDetector(t *testing.T) {
	type args struct {
		osFamily  string
		osName    string
		remoteURL string
		token     string
	}
	tests := []struct {
		name string
		args args
		want DetectorOperation
	}{
		{
			name: "standalone",
			args: args{
				osFamily:  "alpine",
				osName:    "3.7",
				remoteURL: "",
				token:     "",
			},
			want: Detector{},
		},
		{
			name: "rpc client",
			args: args{
				osFamily:  "alpine",
				osName:    "3.7",
				remoteURL: "http://localhost:8080",
				token:     "token",
			},
			want: ospkg.DetectClient{},
		},
		{
			name: "unknown os",
			args: args{
				osFamily:  "unknown",
				osName:    "unknown",
				remoteURL: "http://localhost:8080",
				token:     "token",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDetector(tt.args.osFamily, tt.args.osName, tt.args.remoteURL, tt.args.token)
			assert.IsType(t, tt.want, got, tt.name)
		})
	}
}
