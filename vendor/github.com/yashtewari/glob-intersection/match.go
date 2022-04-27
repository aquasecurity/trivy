package gintersect

import (
	"errors"
)

var (
	errBadImplementation = errors.New("this logical path is invalid")
)

// Match implements single-Token matching, ignoring flags.
// Example: [a-d] and [b-e] match, while [a-z] and [0-9] do not.
func Match(t1 Token, t2 Token) bool {
	var temp Token
	if t1.Type() > t2.Type() {
		temp = t1
		t1 = t2
		t2 = temp
	}

	switch t1.Type() {
	case TTCharacter:
		ch := t1.(*character)

		switch t2.Type() {
		case TTCharacter:
			return matchCharacters(ch, t2.(*character))
		case TTDot:
			return matchCharacterDot(ch, t2.(*dot))
		case TTSet:
			return matchCharacterSet(ch, t2.(*set))
		default:
			panic(errBadImplementation)
		}

	case TTDot:
		d := t1.(*dot)

		switch t2.Type() {
		case TTDot:
			return matchDots(d, t2.(*dot))
		case TTSet:
			return matchDotSet(d, t2.(*set))
		default:
			panic(errBadImplementation)
		}

	case TTSet:
		switch t2.Type() {
		case TTSet:
			return matchSets(t1.(*set), t2.(*set))
		default:
			panic(errBadImplementation)
		}

	default:
		panic(errBadImplementation)

	}
}

func matchCharacters(a *character, b *character) bool {
	return a.Rune() == b.Rune()
}

func matchCharacterDot(a *character, b *dot) bool {
	return true
}

func matchCharacterSet(a *character, b *set) bool {
	_, ok := b.Runes()[a.Rune()]
	return ok
}

func matchDots(a *dot, b *dot) bool {
	return true
}

func matchDotSet(a *dot, b *set) bool {
	return true
}

func matchSets(a *set, b *set) bool {
	for k, _ := range a.Runes() {
		if _, ok := b.Runes()[k]; ok {
			return true
		}
	}

	return false
}
