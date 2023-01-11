package disk_test

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/disk"
)

func TestNew(t *testing.T) {
	type args struct {
		rs    io.ReadSeeker
		cache vm.Cache[string, []byte]
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

			_, err = disk.New(f, nil)
			if err == nil {
				assert.Fail(t, "required error test")
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
