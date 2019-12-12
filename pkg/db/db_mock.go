package db

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (_m *MockClient) NeedsUpdate(a context.Context, b string, c, d bool) (bool, error) {
	ret := _m.Called(a, b, c, d)
	return ret.Bool(0), ret.Error(1)
}

func (_m *MockClient) Download(a context.Context, b string, c bool) error {
	ret := _m.Called(a, b, c)
	return ret.Error(0)

}
