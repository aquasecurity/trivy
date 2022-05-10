package dbi

type Entry struct {
	Value []byte
	Err   error
}

type RpmDBInterface interface {
	Read() <-chan Entry
}
