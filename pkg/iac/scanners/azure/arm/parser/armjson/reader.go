package armjson

import (
	"bufio"
	"io"
)

type PeekReader struct {
	underlying *bufio.Reader
}

func NewPeekReader(reader io.Reader) *PeekReader {
	return &PeekReader{
		underlying: bufio.NewReader(reader),
	}
}

func (r *PeekReader) Next() (rune, error) {
	c, _, err := r.underlying.ReadRune()
	return c, err
}

func (r *PeekReader) Undo() error {
	return r.underlying.UnreadRune()
}

func (r *PeekReader) Peek() (rune, error) {
	c, _, err := r.underlying.ReadRune()
	if err != nil {
		return 0, err
	}
	if err := r.underlying.UnreadRune(); err != nil {
		return 0, err
	}
	return c, nil
}
