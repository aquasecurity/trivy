package github

import (
	"context"
	"io"

	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (_m *MockClient) DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, error) {
	ret := _m.Called(ctx, fileName)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	rc, ok := ret0.(io.ReadCloser)
	if !ok {
		return nil, ret.Error(1)
	}
	return rc, ret.Error(1)
}
