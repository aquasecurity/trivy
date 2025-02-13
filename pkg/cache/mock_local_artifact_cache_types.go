package cache

import (
	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type LocalArtifactCacheClearReturns struct {
	Err error
}

type LocalArtifactCacheClearExpectation struct {
	Returns LocalArtifactCacheClearReturns
}

func (_m *MockLocalArtifactCache) ApplyClearExpectation(e LocalArtifactCacheClearExpectation) {
	var args []any
	_m.On("Clear", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockLocalArtifactCache) ApplyClearExpectations(expectations []LocalArtifactCacheClearExpectation) {
	for _, e := range expectations {
		_m.ApplyClearExpectation(e)
	}
}

type LocalArtifactCacheCloseReturns struct {
	Err error
}

type LocalArtifactCacheCloseExpectation struct {
	Returns LocalArtifactCacheCloseReturns
}

func (_m *MockLocalArtifactCache) ApplyCloseExpectation(e LocalArtifactCacheCloseExpectation) {
	var args []any
	_m.On("Close", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockLocalArtifactCache) ApplyCloseExpectations(expectations []LocalArtifactCacheCloseExpectation) {
	for _, e := range expectations {
		_m.ApplyCloseExpectation(e)
	}
}

type LocalArtifactCacheGetArtifactArgs struct {
	ArtifactID         string
	ArtifactIDAnything bool
}

type LocalArtifactCacheGetArtifactReturns struct {
	ArtifactInfo types.ArtifactInfo
	Err          error
}

type LocalArtifactCacheGetArtifactExpectation struct {
	Args    LocalArtifactCacheGetArtifactArgs
	Returns LocalArtifactCacheGetArtifactReturns
}

func (_m *MockLocalArtifactCache) ApplyGetArtifactExpectation(e LocalArtifactCacheGetArtifactExpectation) {
	var args []any
	if e.Args.ArtifactIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ArtifactID)
	}
	_m.On("GetArtifact", args...).Return(e.Returns.ArtifactInfo, e.Returns.Err).Maybe()
}

func (_m *MockLocalArtifactCache) ApplyGetArtifactExpectations(expectations []LocalArtifactCacheGetArtifactExpectation) {
	for _, e := range expectations {
		_m.ApplyGetArtifactExpectation(e)
	}
}

type LocalArtifactCacheGetBlobArgs struct {
	BlobID         string
	BlobIDAnything bool
}

type LocalArtifactCacheGetBlobReturns struct {
	BlobInfo types.BlobInfo
	Err      error
}

type LocalArtifactCacheGetBlobExpectation struct {
	Args    LocalArtifactCacheGetBlobArgs
	Returns LocalArtifactCacheGetBlobReturns
}

func (_m *MockLocalArtifactCache) ApplyGetBlobExpectation(e LocalArtifactCacheGetBlobExpectation) {
	var args []any
	if e.Args.BlobIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobID)
	}
	_m.On("GetBlob", args...).Return(e.Returns.BlobInfo, e.Returns.Err).Maybe()
}

func (_m *MockLocalArtifactCache) ApplyGetBlobExpectations(expectations []LocalArtifactCacheGetBlobExpectation) {
	for _, e := range expectations {
		_m.ApplyGetBlobExpectation(e)
	}
}
