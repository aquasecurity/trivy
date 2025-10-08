package expressions

type tokenWalker struct {
	tokens          []Token
	currentPosition int
}

func newTokenWalker(tokens []Token) *tokenWalker {
	return &tokenWalker{
		tokens:          tokens,
		currentPosition: 0,
	}
}

func (t *tokenWalker) peek() Token {
	if t.currentPosition >= len(t.tokens) {
		return Token{}
	}
	return t.tokens[t.currentPosition]
}

func (t *tokenWalker) hasNext() bool {
	return t.currentPosition+1 < len(t.tokens)
}

func (t *tokenWalker) unPop() {
	if t.currentPosition > 0 {
		t.currentPosition--
	}
}

func (t *tokenWalker) pop() *Token {
	if !t.hasNext() {
		return nil
	}

	token := t.tokens[t.currentPosition]
	t.currentPosition++
	return &token
}
