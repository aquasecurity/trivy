package ospkg

import (
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/mock"
)

type MockDetector struct {
	mock.Mock
}

type DetectInput struct {
	ImageName string
	OSFamily  string
	OSName    string
	Created   time.Time
	Pkgs      []ftypes.Package
}
type DetectOutput struct {
	Vulns []types.DetectedVulnerability
	Eosl  bool
	Err   error
}
type DetectExpectation struct {
	Args       DetectInput
	ReturnArgs DetectOutput
}

func NewMockDetector(detectExpectations []DetectExpectation) *MockDetector {
	mockDetector := new(MockDetector)
	for _, e := range detectExpectations {
		mockDetector.On("Detect", e.Args.ImageName, e.Args.OSFamily, e.Args.OSName, e.Args.Created, e.Args.Pkgs).Return(
			e.ReturnArgs.Vulns, e.ReturnArgs.Eosl, e.ReturnArgs.Err)
	}
	return mockDetector
}

func (_m *MockDetector) Detect(a string, b string, c string, d time.Time, e []ftypes.Package) ([]types.DetectedVulnerability, bool, error) {
	ret := _m.Called(a, b, c, d, e)
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
