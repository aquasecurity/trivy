package gintersect

// Simplify accepts a Token slice and returns a equivalient Token slice that is shorter/simpler.
// The only simplification currently applied is removing redundant flagged Tokens.
// TODO: Remove unflagged Tokens next to equivalen Tokens with FlagPlus. Example: tt+t == t+
func Simplify(tokens []Token) []Token {
	if len(tokens) == 0 {
		return tokens
	}
	simple := make([]Token, 1, len(tokens))
	simple[0] = tokens[0]

	latest := simple[0]

	for i := 1; i < len(tokens); i++ {
		handled := false
		// Possible simplifications to apply if there is a flag.
		if tokens[i].Flag() != FlagNone && latest.Flag() != FlagNone {
			// If the token contents are the same, then apply simplification.
			if tokens[i].Equal(latest) {
				var flag Flag
				// FlagPlus takes precedence, because:
				//   t+t* == t+
				//   t*t+ == t+
				if tokens[i].Flag() == FlagPlus || latest.Flag() == FlagPlus {
					flag = FlagPlus
				} else {
					flag = FlagStar
				}

				simple[len(simple)-1].SetFlag(flag)
				handled = true
			}
		}

		if !handled {
			latest = tokens[i]
			simple = append(simple, tokens[i])
		}
	}

	return simple
}
