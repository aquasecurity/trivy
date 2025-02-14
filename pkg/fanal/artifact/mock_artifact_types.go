package artifact

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type ArtifactCleanArgs struct {
	Reference         Reference
	ReferenceAnything bool
}

type ArtifactCleanReturns struct {
	_a0 error
}

type ArtifactCleanExpectation struct {
	Args    ArtifactCleanArgs
	Returns ArtifactCleanReturns
}

func (_m *MockArtifact) ApplyCleanExpectation(e ArtifactCleanExpectation) {
	var args []any
	if e.Args.ReferenceAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Reference)
	}
	_m.On("Clean", args...).Return(e.Returns._a0).Maybe()
}

func (_m *MockArtifact) ApplyCleanExpectations(expectations []ArtifactCleanExpectation) {
	for _, e := range expectations {
		_m.ApplyCleanExpectation(e)
	}
}

type ArtifactInspectArgs struct {
	Ctx         context.Context
	CtxAnything bool
}

type ArtifactInspectReturns struct {
	Reference Reference
	Err       error
}

type ArtifactInspectExpectation struct {
	Args    ArtifactInspectArgs
	Returns ArtifactInspectReturns
}

func (_m *MockArtifact) ApplyInspectExpectation(e ArtifactInspectExpectation) {
	var args []any
	if e.Args.CtxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Ctx)
	}
	_m.On("Inspect", args...).Return(e.Returns.Reference, e.Returns.Err).Maybe()
}

func (_m *MockArtifact) ApplyInspectExpectations(expectations []ArtifactInspectExpectation) {
	for _, e := range expectations {
		_m.ApplyInspectExpectation(e)
	}
}
