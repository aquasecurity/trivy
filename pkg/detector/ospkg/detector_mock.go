package ospkg

import (
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/mock"
)

type MockDetector struct {
	mock.Mock
}

func (_m *MockDetector) Detect(a, b string, c []analyzer.Package) ([]types.DetectedVulnerability, bool, error) {
	ret := _m.Called(a, b, c)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, false, ret.Error(2)
	}
	vulns, ok := ret0.([]types.DetectedVulnerability)
	if !ok {
		return nil, false, ret.Error(2)
	}
	return vulns, ret.Bool(1), ret.Error(2)
}
