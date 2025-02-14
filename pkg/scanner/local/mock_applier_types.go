package local

import (
	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type ApplierApplyLayersArgs struct {
	ArtifactID         string
	ArtifactIDAnything bool
	BlobIDs            []string
	BlobIDsAnything    bool
}

type ApplierApplyLayersReturns struct {
	Detail types.ArtifactDetail
	Err    error
}

type ApplierApplyLayersExpectation struct {
	Args    ApplierApplyLayersArgs
	Returns ApplierApplyLayersReturns
}

func (_m *MockApplier) ApplyApplyLayersExpectation(e ApplierApplyLayersExpectation) {
	var args []any
	if e.Args.ArtifactIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ArtifactID)
	}
	if e.Args.BlobIDsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobIDs)
	}
	_m.On("ApplyLayers", args...).Return(e.Returns.Detail, e.Returns.Err).Maybe()
}

func (_m *MockApplier) ApplyApplyLayersExpectations(expectations []ApplierApplyLayersExpectation) {
	for _, e := range expectations {
		_m.ApplyApplyLayersExpectation(e)
	}
}
