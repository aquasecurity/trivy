package gintersect

var (
	samplesInitialized = false

	testCharacters     map[rune]Token
	testCharactersPlus map[rune]Token
	testCharactersStar map[rune]Token

	testDot, testDotPlus, testDotStar Token

	testLowerAlphaSet, testLowerAlphaSetPlus, lowerAplhaSetStar     Token
	testUpperAlphaSet, testUpperAlphaSetPlus, testUpperAlphaSetStar Token
	testNumSet, testNumSetPlus, testNumSetStar                      Token
	testSymbolSet, testSymbolSetPlus, testSymbolSetStar             Token

	testEmptySet Token
)

func initializeTestSamples() {
	if samplesInitialized {
		return
	}

	testCharacters, testCharactersPlus, testCharactersStar = make(map[rune]Token), make(map[rune]Token), make(map[rune]Token)

	testDot, testDotPlus, testDotStar = NewDot(), NewDot(), NewDot()
	testDotPlus.SetFlag(FlagPlus)
	testDotStar.SetFlag(FlagStar)

	var runes []rune
	runes = makeRunes('a', 'z')

	testLowerAlphaSet, testLowerAlphaSetPlus, lowerAplhaSetStar = NewSet(runes), NewSet(runes), NewSet(runes)
	testLowerAlphaSetPlus.SetFlag(FlagPlus)
	lowerAplhaSetStar.SetFlag(FlagStar)

	runes = makeRunes('A', 'Z')

	testUpperAlphaSet, testUpperAlphaSetPlus, testUpperAlphaSetStar = NewSet(runes), NewSet(runes), NewSet(runes)
	testUpperAlphaSetPlus.SetFlag(FlagPlus)
	testUpperAlphaSetStar.SetFlag(FlagStar)

	runes = makeRunes('0', '9')

	testNumSet, testNumSetPlus, testNumSetStar = NewSet(runes), NewSet(runes), NewSet(runes)
	testNumSetPlus.SetFlag(FlagPlus)
	testNumSetStar.SetFlag(FlagStar)

	runes = makeRunes('!', '/')

	testSymbolSet, testSymbolSetPlus, testSymbolSetStar = NewSet(runes), NewSet(runes), NewSet(runes)
	testSymbolSetPlus.SetFlag(FlagPlus)
	testSymbolSetStar.SetFlag(FlagStar)

	testEmptySet = NewSet([]rune{})

	samplesInitialized = true
}

func makeRunes(from rune, to rune) []rune {
	runes := make([]rune, 0, 30)
	for r := from; r <= to; r++ {
		runes = append(runes, r)
		addToCharacters(r)
	}

	return runes
}

func addToCharacters(r rune) {
	var t Token

	t = NewCharacter(r)
	testCharacters[r] = t

	t = NewCharacter(r)
	t.SetFlag(FlagPlus)
	testCharactersPlus[r] = t

	t = NewCharacter(r)
	t.SetFlag(FlagStar)
	testCharactersStar[r] = t
}
