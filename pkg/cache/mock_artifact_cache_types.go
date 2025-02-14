package cache

import (
	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type ArtifactCacheDeleteBlobsArgs struct {
	BlobIDs         []string
	BlobIDsAnything bool
}

type ArtifactCacheDeleteBlobsReturns struct {
	_a0 error
}

type ArtifactCacheDeleteBlobsExpectation struct {
	Args    ArtifactCacheDeleteBlobsArgs
	Returns ArtifactCacheDeleteBlobsReturns
}

func (_m *MockArtifactCache) ApplyDeleteBlobsExpectation(e ArtifactCacheDeleteBlobsExpectation) {
	var args []any
	if e.Args.BlobIDsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobIDs)
	}
	_m.On("DeleteBlobs", args...).Return(e.Returns._a0).Maybe()
}

func (_m *MockArtifactCache) ApplyDeleteBlobsExpectations(expectations []ArtifactCacheDeleteBlobsExpectation) {
	for _, e := range expectations {
		_m.ApplyDeleteBlobsExpectation(e)
	}
}

type ArtifactCacheMissingBlobsArgs struct {
	ArtifactID         string
	ArtifactIDAnything bool
	BlobIDs            []string
	BlobIDsAnything    bool
}

type ArtifactCacheMissingBlobsReturns struct {
	MissingArtifact bool
	MissingBlobIDs  []string
	Err             error
}

type ArtifactCacheMissingBlobsExpectation struct {
	Args    ArtifactCacheMissingBlobsArgs
	Returns ArtifactCacheMissingBlobsReturns
}

func (_m *MockArtifactCache) ApplyMissingBlobsExpectation(e ArtifactCacheMissingBlobsExpectation) {
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

func (_m *MockArtifactCache) ApplyMissingBlobsExpectations(expectations []ArtifactCacheMissingBlobsExpectation) {
	for _, e := range expectations {
		_m.ApplyMissingBlobsExpectation(e)
	}
}

type ArtifactCachePutArtifactArgs struct {
	ArtifactID           string
	ArtifactIDAnything   bool
	ArtifactInfo         types.ArtifactInfo
	ArtifactInfoAnything bool
}

type ArtifactCachePutArtifactReturns struct {
	Err error
}

type ArtifactCachePutArtifactExpectation struct {
	Args    ArtifactCachePutArtifactArgs
	Returns ArtifactCachePutArtifactReturns
}

func (_m *MockArtifactCache) ApplyPutArtifactExpectation(e ArtifactCachePutArtifactExpectation) {
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

func (_m *MockArtifactCache) ApplyPutArtifactExpectations(expectations []ArtifactCachePutArtifactExpectation) {
	for _, e := range expectations {
		_m.ApplyPutArtifactExpectation(e)
	}
}

type ArtifactCachePutBlobArgs struct {
	BlobID           string
	BlobIDAnything   bool
	BlobInfo         types.BlobInfo
	BlobInfoAnything bool
}

type ArtifactCachePutBlobReturns struct {
	Err error
}

type ArtifactCachePutBlobExpectation struct {
	Args    ArtifactCachePutBlobArgs
	Returns ArtifactCachePutBlobReturns
}

func (_m *MockArtifactCache) ApplyPutBlobExpectation(e ArtifactCachePutBlobExpectation) *mock.Call {
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
	return _m.On("PutBlob", args...).Return(e.Returns.Err).Maybe()
}

func (_m *MockArtifactCache) ApplyPutBlobExpectations(expectations []ArtifactCachePutBlobExpectation) {
	for _, e := range expectations {
		_m.ApplyPutBlobExpectation(e)
	}
}
