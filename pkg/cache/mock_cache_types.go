package cache

import (
	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type CacheClearReturns struct {
	Err error
}

type CacheClearExpectation struct {
	Returns CacheClearReturns
}

func (_m *MockCache) ApplyClearExpectation(e CacheClearExpectation) {
	var args []any
	_m.On("Clear", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyClearExpectations(expectations []CacheClearExpectation) {
	for _, e := range expectations {
		_m.ApplyClearExpectation(e)
	}
}

type CacheCloseReturns struct {
	Err error
}

type CacheCloseExpectation struct {
	Returns CacheCloseReturns
}

func (_m *MockCache) ApplyCloseExpectation(e CacheCloseExpectation) {
	var args []any
	_m.On("Close", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyCloseExpectations(expectations []CacheCloseExpectation) {
	for _, e := range expectations {
		_m.ApplyCloseExpectation(e)
	}
}

type CacheDeleteBlobArgs struct {
	BlobID         string
	BlobIDAnything bool
}

type CacheDeleteBlobReturns struct {
	_a0 error
}

type CacheDeleteBlobExpectation struct {
	Args    CacheDeleteBlobArgs
	Returns CacheDeleteBlobReturns
}

func (_m *MockCache) ApplyDeleteBlobExpectation(e CacheDeleteBlobExpectation) {
	var args []any
	if e.Args.BlobIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobID)
	}
	_m.On("DeleteBlob", args...).Return(e.Returns._a0).Maybe()
}

func (_m *MockCache) ApplyDeleteBlobExpectations(expectations []CacheDeleteBlobExpectation) {
	for _, e := range expectations {
		_m.ApplyDeleteBlobExpectation(e)
	}
}

// DeleteBlob provides a mock function with given fields: blobID
func (_m *MockCache) DeleteBlob(blobID string) error {
	ret := _m.Called(blobID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(blobID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type CacheGetArtifactArgs struct {
	ArtifactID         string
	ArtifactIDAnything bool
}

type CacheGetArtifactReturns struct {
	ArtifactInfo types.ArtifactInfo
	Err          error
}

type CacheGetArtifactExpectation struct {
	Args    CacheGetArtifactArgs
	Returns CacheGetArtifactReturns
}

func (_m *MockCache) ApplyGetArtifactExpectation(e CacheGetArtifactExpectation) {
	var args []any
	if e.Args.ArtifactIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ArtifactID)
	}
	_m.On("GetArtifact", args...).Return(e.Returns.ArtifactInfo, e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyGetArtifactExpectations(expectations []CacheGetArtifactExpectation) {
	for _, e := range expectations {
		_m.ApplyGetArtifactExpectation(e)
	}
}

type CacheGetBlobArgs struct {
	BlobID         string
	BlobIDAnything bool
}

type CacheGetBlobReturns struct {
	BlobInfo types.BlobInfo
	Err      error
}

type CacheGetBlobExpectation struct {
	Args    CacheGetBlobArgs
	Returns CacheGetBlobReturns
}

func (_m *MockCache) ApplyGetBlobExpectation(e CacheGetBlobExpectation) {
	var args []any
	if e.Args.BlobIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobID)
	}
	_m.On("GetBlob", args...).Return(e.Returns.BlobInfo, e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyGetBlobExpectations(expectations []CacheGetBlobExpectation) {
	for _, e := range expectations {
		_m.ApplyGetBlobExpectation(e)
	}
}

type CacheMissingBlobsArgs struct {
	ArtifactID         string
	ArtifactIDAnything bool
	BlobIDs            []string
	BlobIDsAnything    bool
}

type CacheMissingBlobsReturns struct {
	MissingArtifact bool
	MissingBlobIDs  []string
	Err             error
}

type CacheMissingBlobsExpectation struct {
	Args    CacheMissingBlobsArgs
	Returns CacheMissingBlobsReturns
}

func (_m *MockCache) ApplyMissingBlobsExpectation(e CacheMissingBlobsExpectation) {
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
	_m.On("MissingBlobs", args...).Return(e.Returns.MissingArtifact, e.Returns.MissingBlobIDs, e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyMissingBlobsExpectations(expectations []CacheMissingBlobsExpectation) {
	for _, e := range expectations {
		_m.ApplyMissingBlobsExpectation(e)
	}
}

type CachePutArtifactArgs struct {
	ArtifactID           string
	ArtifactIDAnything   bool
	ArtifactInfo         types.ArtifactInfo
	ArtifactInfoAnything bool
}

type CachePutArtifactReturns struct {
	Err error
}

type CachePutArtifactExpectation struct {
	Args    CachePutArtifactArgs
	Returns CachePutArtifactReturns
}

func (_m *MockCache) ApplyPutArtifactExpectation(e CachePutArtifactExpectation) {
	var args []any
	if e.Args.ArtifactIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ArtifactID)
	}
	if e.Args.ArtifactInfoAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ArtifactInfo)
	}
	_m.On("PutArtifact", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyPutArtifactExpectations(expectations []CachePutArtifactExpectation) {
	for _, e := range expectations {
		_m.ApplyPutArtifactExpectation(e)
	}
}

type CachePutBlobArgs struct {
	BlobID           string
	BlobIDAnything   bool
	BlobInfo         types.BlobInfo
	BlobInfoAnything bool
}

type CachePutBlobReturns struct {
	Err error
}

type CachePutBlobExpectation struct {
	Args    CachePutBlobArgs
	Returns CachePutBlobReturns
}

func (_m *MockCache) ApplyPutBlobExpectation(e CachePutBlobExpectation) {
	var args []any
	if e.Args.BlobIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobID)
	}
	if e.Args.BlobInfoAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobInfo)
	}
	_m.On("PutBlob", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockCache) ApplyPutBlobExpectations(expectations []CachePutBlobExpectation) {
	for _, e := range expectations {
		_m.ApplyPutBlobExpectation(e)
	}
}
