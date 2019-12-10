package ospkg

import (
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/mock"
)

type MockDetector struct {
	mock.Mock
}

type DetectInput struct {
	OSFamily string
	OSName   string
	Pkgs     []analyzer.Package
}
type DetectOutput struct {
	Vulns []types.DetectedVulnerability
	Err   error
}
type DetectExpectation struct {
	Args       DetectInput
	ReturnArgs DetectOutput
}

func NewMockDetector(detectExpectations []DetectExpectation) *MockDetector {
	mockDetector := new(MockDetector)
	for _, e := range detectExpectations {
		mockDetector.On("Detect", e.Args.OSFamily, e.Args.OSName, e.Args.Pkgs).Return(
			e.ReturnArgs.Vulns, e.ReturnArgs.Err)
	}
	return mockDetector
}

func (_m *MockDetector) Detect(a, b string, c []analyzer.Package) ([]types.DetectedVulnerability, error) {
	ret := _m.Called(a, b, c)
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
