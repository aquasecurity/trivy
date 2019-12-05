package detector

import (
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/mock"
)

type MockDetector struct {
	mock.Mock
}

func (_m *MockDetector) Detect(a string, b []ptypes.Library) ([]types.DetectedVulnerability, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	vulns, ok := ret0.([]types.DetectedVulnerability)
	if !ok {
		return nil, ret.Error(1)
	}
	return vulns, ret.Error(1)
}
