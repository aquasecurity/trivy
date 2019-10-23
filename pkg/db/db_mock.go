package db

import (
	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/mock"
)

type MockDBConfig struct {
	mock.Mock
}

func (_m *MockDBConfig) SetVersion(version int) error {
	ret := _m.Called(version)
	return ret.Error(0)
}

func (_m *MockDBConfig) Update(a, b, c string, d interface{}) error {
	ret := _m.Called(a, b, c, d)
	return ret.Error(0)
}

func (_m *MockDBConfig) BatchUpdate(f func(*bolt.Tx) error) error {
	ret := _m.Called(f)
	return ret.Error(0)
}

func (_m *MockDBConfig) PutNestedBucket(a *bolt.Tx, b, c, d string, e interface{}) error {
	ret := _m.Called(a, b, c, d, e)
	return ret.Error(0)
}

func (_m *MockDBConfig) ForEach(a string, b string) (map[string][]byte, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	r, ok := ret0.(map[string][]byte)
	if !ok {
		return nil, ret.Error(1)
	}
	return r, ret.Error(1)
}
