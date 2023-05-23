package disk_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/vm/disk"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVMDK_NewReader(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		wantErr  string
	}{
		// TODO: add valid tests
		{
			name:     "invalid vmdk file",
			fileName: "testdata/invalid.vmdk",
			wantErr:  "invalid signature error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := disk.VMDK{}

			f, err := os.Open(tt.fileName)
			require.NoError(t, err)
			defer f.Close()

			_, err = v.NewReader(f, nil)
			if err == nil {
				assert.Fail(t, "required error test")
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
