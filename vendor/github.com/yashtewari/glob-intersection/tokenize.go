package gintersect

import (
	"fmt"

	"errors"
)

// Modifier is a special character that affects lexical analysis.
type Modifier uint

const (
	ModifierBackslash Modifier = iota
)

var (
	// Special runes.
	tokenTypeRunes = map[rune]TokenType{
		'.': TTDot,
		'[': TTSet,
		']': TTSet,
	}
	flagRunes = map[rune]Flag{
		'+': FlagPlus,
		'*': FlagStar,
	}
	modifierRunes = map[rune]Modifier{
		'\\': ModifierBackslash,
	}

	// Errors.
	ErrInvalidInput = errors.New("the input provided is invalid")
	errEndOfInput   = errors.New("reached end of input")
)

// Tokenize converts a rune slice into a Token slice.
func Tokenize(input []rune) ([]Token, error) {
	tokens := []Token{}
	for i, t, err := nextToken(0, input); err != errEndOfInput; i, t, err = nextToken(i, input) {
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, t)
	}

	return tokens, nil
}

// nextToken yields the Token starting at the given index of input, and newIndex at which the next Token should start.
func nextToken(index int, input []rune) (newIndex int, token Token, err error) {
	var r rune
	var escaped bool

	newIndex, r, escaped, err = nextRune(index, input)
	if err != nil {
		return
	}

	if !escaped {
		if ttype, ok := tokenTypeRunes[r]; ok {
			switch ttype {
			case TTDot:
				token = NewDot()

			case TTSet:
				if r == ']' {
					err = invalidInputMessageErrorf(input, newIndex, "set-close ']' with no preceding '[': %w", ErrInvalidInput)
					return
				}

				newIndex, token, err = nextTokenSet(newIndex, input)
				if err != nil {
					return
				}

			default:
				panic(fmt.Errorf("encountered unhandled token type %v: %w", ttype, errBadImplementation))
			}

		} else if _, ok := flagRunes[r]; ok {
			err = invalidInputMessageErrorf(input, newIndex, "flag '%s' must be preceded by a non-flag: %w", string(r), ErrInvalidInput)
			return

		} else if m, ok := modifierRunes[r]; ok {
			panic(fmt.Errorf("encountered unhandled modifier %v: %w", m, errBadImplementation))
		} else {
			// Nothing special to do.
			token = NewCharacter(r)
		}
	} else {
		// Nothing special to do.
		token = NewCharacter(r)
	}

	var f Flag
	newIndex, f, err = nextFlag(newIndex, input)
	if err == errEndOfInput {
		// Let this err be passed in the next cycle, after the current token is consumed.
		err = nil
	} else if err != nil {
		return
	}

	token.SetFlag(f)

	return
}

// nextTokenSet yields a Token having type TokenSet and starting at the given index of input.
// The next Token/Flag should start at newIndex.
func nextTokenSet(index int, input []rune) (newIndex int, t Token, err error) {
	var r, prev rune
	var escaped bool

	runes := make([]rune, 0, 30)
	complete, prevExists := false, false

	newIndex, r, escaped, err = nextRune(index, input)
	// If errEndOfInput is encountered, flow of control proceeds to the end of the function,
	// where the error is handled.
	if err != nil && err != errEndOfInput {
		return
	}

	for ; err != errEndOfInput; newIndex, r, escaped, err = nextRune(newIndex, input) {
		if err != nil {
			return
		}

		if !escaped {
			// Handle symbols.
			switch r {
			case '-':
				if !prevExists {
					err = invalidInputMessageErrorf(input, newIndex, "range character '-' must be preceded by a Unicode character: %w", ErrInvalidInput)
					return
				}
				if newIndex >= len(input)-1 {
					err = invalidInputMessageErrorf(input, newIndex, "range character '-' must be followed by a Unicode character: %w", ErrInvalidInput)
					return
				}

				// Get the next rune to know the extent of the range.
				newIndex, r, escaped, err = nextRune(newIndex, input)

				if !escaped {
					if r == ']' || r == '-' {
						err = invalidInputMessageErrorf(input, newIndex, "range character '-' cannot be followed by a special symbol: %w", ErrInvalidInput)
						return
					}
				}
				if r < prev {
					err = invalidInputMessageErrorf(input, newIndex, "range is out of order: '%s' comes before '%s' in Unicode: %w", string(r), string(prev), ErrInvalidInput)
					return
				}

				for x := prev; x <= r; x++ {
					runes = append(runes, x)
				}

				prevExists = false

			case ']':
				complete = true

			// Nothing special to do.
			default:
				runes = append(runes, r)
				prev, prevExists = r, true
			}
		} else {
			// Nothing special to do.
			runes = append(runes, r)
			prev, prevExists = r, true
		}

		// Don't move the index forward if the set is complete.
		if complete {
			break
		}
	}

	// End of input is reached before the set completes.
	if !complete {
		err = invalidInputMessageErrorf(input, newIndex, "found [ without matching ]: %w", ErrInvalidInput)
	} else {
		t = NewSet(runes)
	}

	return
}

// nextFlag yields the Flag starting at the given index of input, if any.
// The next Token should start at newIndex.
func nextFlag(index int, input []rune) (newIndex int, f Flag, err error) {
	var escaped, ok bool
	var r rune

	f = FlagNone

	newIndex, r, escaped, err = nextRune(index, input)
	if err != nil {
		return
	}

	if !escaped {
		// Revert back to index for later consumption.
		if f, ok = flagRunes[r]; !ok {
			newIndex = index
		}
	} else {
		// Revert back to index for later consumption.
		newIndex = index
	}

	return
}

// nextRune yields the rune starting (with modifiers) at the given index of input, with boolean escaped describing whether the rune is escaped.
// The next rune should start at newIndex.
func nextRune(index int, input []rune) (newIndex int, r rune, escaped bool, err error) {
	if index >= len(input) {
		newIndex = index
		err = errEndOfInput
		return
	}

	if m, ok := modifierRunes[input[index]]; ok {
		switch m {

		case ModifierBackslash:
			if index < len(input)-1 {
				newIndex, r, escaped = index+2, input[index+1], true
			} else if index == len(input)-1 {
				err = invalidInputMessageErrorf(input, index, "input ends with a \\ (escape) character: %w", ErrInvalidInput)
			}
		default:
			panic(fmt.Errorf("encountered unhandled modifier %v: %w", m, errBadImplementation))
		}
	} else {
		newIndex, r, escaped = index+1, input[index], false
	}

	return
}

// invalidInputMessageErrorf wraps the message describing invalid input with the input itself and index at which it is invalid.
func invalidInputMessageErrorf(input []rune, index int, message string, args ...interface{}) error {
	message = fmt.Sprintf("input:%s, pos:%d, %s", string(input), index, message)
	return fmt.Errorf(message, args...)
}
