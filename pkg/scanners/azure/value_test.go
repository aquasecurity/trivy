package azure

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func Test_ValueAsInt(t *testing.T) {
	val := NewValue(int64(10), types.NewTestMisconfigMetadata())
	assert.Equal(t, 10, val.AsInt())
}
