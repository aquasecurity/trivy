package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_FilenameWindowsFriendly(t *testing.T) {

	tests := []struct {
		name     string
		fileName string
		want     string
	}{
		{
			name:     "name with invalid char - colon",
			fileName: `kube-system-Role-system:controller:bootstrap-signer-2934213283.yaml`,
			want:     `kube-system-Role-system_controller_bootstrap-signer-2934213283.yaml`,
		},
		{
			name:     "name with no invalid chars",
			fileName: `kube-system-Role-system-controller-bootstrap-signer-2934213283.yaml`,
			want:     `kube-system-Role-system-controller-bootstrap-signer-2934213283.yaml`,
		},
		{
			name:     "name with no invalid - slash",
			fileName: "-ClusterRoleBinding-system\\basic-user-725844313.yaml",
			want:     `-ClusterRoleBinding-system_basic-user-725844313.yaml`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := filenameWindowsFriendly(test.fileName)
			assert.Equal(t, test.want, got)
		})
	}
}
