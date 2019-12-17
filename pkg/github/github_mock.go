package github

import (
	"context"
	"io"
	"os"

	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

type DownloadDBInput struct {
	FileName string
}
type DownloadDBOutput struct {
	FileName string
	Size     int
	Err      error
}
type DownloadDBExpectation struct {
	Args       DownloadDBInput
	ReturnArgs DownloadDBOutput
}

func NewMockClient(downloadDBExpectations []DownloadDBExpectation) (*MockClient, error) {
	mockDetector := new(MockClient)
	for _, e := range downloadDBExpectations {
		var rc io.ReadCloser
		if e.ReturnArgs.FileName != "" {
			f, err := os.Open(e.ReturnArgs.FileName)
			if err != nil {
				return nil, err
			}
			rc = f
		}

		mockDetector.On("DownloadDB", mock.Anything, e.Args.FileName).Return(
			rc, e.ReturnArgs.Size, e.ReturnArgs.Err)
	}
	return mockDetector, nil
}

func (_m *MockClient) DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, int, error) {
	ret := _m.Called(ctx, fileName)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Int(1), ret.Error(2)
	}
	rc, ok := ret0.(io.ReadCloser)
	if !ok {
		return nil, ret.Int(1), ret.Error(2)
	}
	return rc, ret.Int(1), ret.Error(2)
}
