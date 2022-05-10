package jfather

import "strconv"

var escapes = map[rune]string{
	'\\': "\\",
	'/':  "/",
	'"':  "\"",
	'n':  "\n",
	'r':  "\r",
	'b':  "\b",
	'f':  "\f",
	't':  "\t",
}

func (p *parser) parseString() (Node, error) {

	n := p.newNode(KindString)

	b, err := p.next()
	if err != nil {
		return nil, err
	}

	if b != '"' {
		return nil, p.makeError("expecting string delimiter")
	}

	var str string

	var inEscape bool
	var inHex bool
	var hex []rune

	for {
		c, err := p.next()
		if err != nil {
			return nil, err
		}
		if inHex {
			switch {
			case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c >= '0' && c <= '9':
				hex = append(hex, c)
				if len(hex) == 4 {
					inHex = false
					char, err := strconv.Unquote("\\u" + string(hex))
					if err != nil {
						return nil, p.makeError("invalid unicode character '%s'", err)
					}
					str += char
					hex = nil
				}
			default:
				return nil, p.makeError("invalid hexedecimal escape sequence '\\%s%c'", string(hex), c)
			}
		} else if inEscape {
			inEscape = false
			if c == 'u' {
				inHex = true
				continue
			}
			seq, ok := escapes[c]
			if !ok {
				return nil, p.makeError("invalid escape sequence '\\%c'", c)
			}
			str += seq
		} else {
			switch c {
			case '\\':
				inEscape = true
			case '"':
				n.raw = str
				n.end = p.position
				return n, nil
			default:
				if c < 0x20 || c > 0x10FFFF {
					return nil, p.makeError("invalid unescaped character '0x%X'", c)
				}
				str += string(c)
			}
		}

	}
}
