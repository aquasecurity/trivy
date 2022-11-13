package vm_test

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"
)

func TestNew(t *testing.T) {
	type args struct {
		rs    io.ReadSeeker
		cache vm.Cache
	}
	tests := []struct {
		name     string
		fileName string
		wantErr  string
	}{
		{
			name:     "invalid vm file",
			fileName: "testdata/invalid.vmdk",
			wantErr:  "virtual machine can not be detected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.fileName)
			require.NoError(t, err)

			_, err = vm.New(f, nil)
			if err == nil {
				assert.Fail(t, "required error test")
			}
			assert.Contains(t, tt.wantErr, err.Error())
		})
	}
}
