package vmdk_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVMDK_NewVMReader(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		wantErr  string
	}{
		{
			name:     "invalid vmdk file",
			fileName: "testdata/invalid.vmdk",
			wantErr:  "invalid signature error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			V := vmdk.VMDK{}

			f, err := os.Open(tt.fileName)
			require.NoError(t, err)

			_, err = V.NewVMReader(f, nil)
			if err == nil {
				assert.Fail(t, "required error test")
			}
			assert.Contains(t, tt.wantErr, err.Error())
		})
	}
}
