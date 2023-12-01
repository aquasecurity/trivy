package armjson

import (
	"errors"
	"io"
)

func (p *parser) parseWhitespace() error {
	for {
		b, err := p.peeker.Peek()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch b {
		case 0x0d, 0x20, 0x09:
		case 0x0a:
			p.position.Column = 1
			p.position.Line++
		default:
			return nil
		}
		if _, err := p.next(); err != nil {
			return err
		}
	}
}
