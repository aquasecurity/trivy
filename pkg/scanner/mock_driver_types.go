package scanner

import (
	"context"

	"github.com/stretchr/testify/mock"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type DriverScanArgs struct {
	Ctx              context.Context
	CtxAnything      bool
	Target           string
	TargetAnything   bool
	ImageID          string
	ImageIDAnything  bool
	LayerIDs         []string
	LayerIDsAnything bool
	Options          types.ScanOptions
	OptionsAnything  bool
}

type DriverScanReturns struct {
	Results types.Results
	OsFound ftypes.OS
	Err     error
}

type DriverScanExpectation struct {
	Args    DriverScanArgs
	Returns DriverScanReturns
}

func (_m *MockDriver) ApplyScanExpectation(e DriverScanExpectation) {
	var args []any
	if e.Args.CtxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Ctx)
	}
	if e.Args.TargetAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Target)
	}
	if e.Args.ImageIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ImageID)
	}
	if e.Args.LayerIDsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.LayerIDs)
	}
	if e.Args.OptionsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Options)
	}
	_m.On("Scan", args...).Return(e.Returns.Results, e.Returns.OsFound, e.Returns.Err).Maybe()
}

func (_m *MockDriver) ApplyScanExpectations(expectations []DriverScanExpectation) {
	for _, e := range expectations {
		_m.ApplyScanExpectation(e)
	}
}
