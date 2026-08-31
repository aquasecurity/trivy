package secret

import (
	"cmp"
	"slices"
)

// keywordIndex finds the keywords of a set of rules in content and reports
// which of the rules can match it.
//
// It is an Aho-Corasick automaton over the keywords of every rule at once.
//
// Matching ignores ASCII case. The keywords are folded when the index is built
// and the content is folded as it is read. Unicode case is not folded, so a
// keyword spelled with a non-ASCII character that lowercases into ASCII, such
// as U+212A KELVIN SIGN, is not found.
//
// A keywordIndex is safe for concurrent use by multiple goroutines.
type keywordIndex struct {
	// trans is the transition table, a row of 256 entries per state, one entry
	// per byte value, so a scan does one lookup per byte of content and never
	// follows a failure link. An entry holds the target state already multiplied
	// by rowLen, and its high bit is set when that state ends a keyword.
	trans []uint32

	// outputs holds the keyword ids to report for each state. The list has the
	// keyword that ends in the state and every keyword that is a suffix of it.
	// A state where no keyword ends has nil.
	outputs [][]int32

	// ruleMasks holds the keyword ids of each rule, in the order the rules were
	// given. A rule that always runs has a nil mask.
	ruleMasks []bitset

	// keywords is the number of distinct keywords.
	keywords int

	// maxKeyword is the length of the longest keyword.
	maxKeyword int
}

const (
	// rowLen is the number of entries in one state's row.
	rowLen = 256

	// matchFlag marks a trans entry whose target state ends a keyword.
	matchFlag = uint32(1) << 31
)

// newKeywordIndex builds an index over the keywords of the given rules.
// It returns nil when no rule has keywords.
func newKeywordIndex(rules []Rule) *keywordIndex {
	patterns, ids := collectKeywords(rules)
	if len(patterns) == 0 {
		return nil
	}

	longest := slices.MaxFunc(patterns, func(a, b string) int {
		return cmp.Compare(len(a), len(b))
	})

	idx := &keywordIndex{
		ruleMasks:  buildRuleMasks(rules, ids),
		keywords:   len(patterns),
		maxKeyword: len(longest),
	}
	idx.compile(patterns)
	return idx
}

// collectKeywords returns the unique folded keywords of the rules, in the order
// they appear. The map holds the id of every keyword, which is its position in
// the slice.
func collectKeywords(rules []Rule) ([]string, map[string]int32) {
	var patterns []string
	ids := make(map[string]int32)
	for _, rule := range rules {
		for _, keyword := range rule.Keywords {
			folded := foldASCIIString(keyword)
			if folded == "" {
				continue
			}
			if _, ok := ids[folded]; ok {
				continue
			}
			ids[folded] = int32(len(patterns))
			patterns = append(patterns, folded)
		}
	}
	return patterns, ids
}

// buildRuleMasks returns the set of keyword ids of each rule, in the order the
// rules were given.
func buildRuleMasks(rules []Rule, ids map[string]int32) []bitset {
	masks := make([]bitset, len(rules))
	for i, rule := range rules {
		// An empty keyword occurs in any content, so a rule that has one always
		// runs, as does a rule with no keywords. Both keep a nil mask.
		if len(rule.Keywords) == 0 || slices.Contains(rule.Keywords, "") {
			continue
		}
		mask := newBitset(len(ids))
		for _, keyword := range rule.Keywords {
			mask.add(ids[foldASCIIString(keyword)])
		}
		masks[i] = mask
	}
	return masks
}

func (idx *keywordIndex) row(state uint32) []uint32 {
	return idx.trans[int(state)*rowLen : int(state)*rowLen+rowLen]
}

// compile turns the patterns into the transition table and the outputs.
// The patterns must already be ASCII folded.
func (idx *keywordIndex) compile(patterns []string) {
	idx.buildStates(patterns)
	idx.foldUpperCase()
	idx.premultiply()
}

// buildStates fills the transition table and the outputs. A state also takes
// the keywords of its failure state, so a keyword nested in a longer one is
// reported too.
func (idx *keywordIndex) buildStates(patterns []string) {
	edges, ends := buildTrie(patterns)
	states := len(edges)
	idx.trans = make([]uint32, states*rowLen)
	// Fill the rows breadth first. Each row starts as a copy of the row of its
	// failure state, which is shallower and already filled, and then the real
	// edges are written over it. A byte with no edge anywhere leads to state 0,
	// and that is the zero value, so nothing has to be written for it.
	fail := make([]uint32, states)
	queue := make([]uint32, 0, states)
	for c, next := range edges[0] {
		idx.trans[int(c)] = next
		queue = append(queue, next)
	}
	for i := 0; i < len(queue); i++ {
		state := queue[i]
		row := idx.row(state)
		failRow := idx.row(fail[state])
		copy(row, failRow)
		for c, next := range edges[state] {
			fail[next] = failRow[c]
			row[c] = next
			queue = append(queue, next)
		}
		ends[state] = append(ends[state], ends[fail[state]]...)
	}
	idx.outputs = ends
}

// buildTrie builds a plain trie over the patterns, one state per distinct
// prefix, and returns its edges and the ids of the patterns ending in each
// state.
func buildTrie(patterns []string) (edges []map[byte]uint32, ends [][]int32) {
	edges = []map[byte]uint32{{}}
	ends = [][]int32{nil}
	for id, pattern := range patterns {
		state := uint32(0)
		for i := 0; i < len(pattern); i++ {
			c := pattern[i]
			next, ok := edges[state][c]
			if !ok {
				edges = append(edges, map[byte]uint32{})
				ends = append(ends, nil)
				next = uint32(len(edges) - 1)
				edges[state][c] = next
			}
			state = next
		}
		ends[state] = append(ends[state], int32(id))
	}
	return edges, ends
}

// foldUpperCase copies the a-z entries of every row onto the A-Z columns. The
// scan then ignores the case of the content without making a lowercase copy.
func (idx *keywordIndex) foldUpperCase() {
	for i := 0; i < len(idx.trans); i += rowLen {
		row := idx.trans[i : i+rowLen]
		for c := byte('A'); c <= 'Z'; c++ {
			row[c] = row[c+'a'-'A']
		}
	}
}

// premultiply turns every entry from the number of the target state into the
// offset of that state's row, and marks the entries whose state ends a keyword.
// The scan then needs no shift and no lookup in outputs on an ordinary byte.
func (idx *keywordIndex) premultiply() {
	for i, next := range idx.trans {
		entry := next * rowLen
		if len(idx.outputs[next]) != 0 {
			entry |= matchFlag
		}
		idx.trans[i] = entry
	}
}

// splitLen is the shortest content worth splitting between two chains. Below
// that the halves overlap by so much that the split does not pay off.
const splitLen = 512

// find returns the set of keywords occurring in content.
func (idx *keywordIndex) find(content []byte) bitset {
	if idx == nil {
		return nil
	}
	found := newBitset(idx.keywords)
	if len(content) < max(splitLen, idx.maxKeyword) {
		idx.walk(content, 0, found)
		return found
	}

	// One chain spends most of its time waiting for the load that gives it the
	// next state, and the loop has nothing else to run meanwhile. Longer content
	// is walked by two chains over two halves, which wait at the same time. The
	// split is placed so that both chains read about the same number of bytes.
	//
	// The second half starts one keyword short of the split, so that a keyword
	// lying across the split is read by that chain from its first byte. The
	// halves therefore overlap, and a keyword ending inside the overlap is found
	// by both chains, which a set does not mind.
	mid := (len(content) + idx.maxKeyword - 1) / 2
	first := content[:mid]
	second := content[mid-idx.maxKeyword+1:]

	trans := idx.trans
	s1, s2 := uint32(0), uint32(0)
	head := second[:len(first)]
	for i, c := range first {
		e1 := trans[s1+uint32(c)]
		e2 := trans[s2+uint32(head[i])]
		if e1&matchFlag == 0 {
			s1 = e1
		} else {
			s1 = e1 &^ matchFlag
			idx.collect(s1, found)
		}
		if e2&matchFlag == 0 {
			s2 = e2
		} else {
			s2 = e2 &^ matchFlag
			idx.collect(s2, found)
		}
	}
	idx.walk(second[len(first):], s2, found)
	return found
}

// walk runs one chain of states over content, starting from state, and adds
// every keyword the chain completes to found.
func (idx *keywordIndex) walk(content []byte, state uint32, found bitset) {
	trans := idx.trans
	for _, c := range content {
		e := trans[state+uint32(c)]
		if e&matchFlag == 0 {
			state = e
			continue
		}
		state = e &^ matchFlag
		idx.collect(state, found)
	}
}

// collect adds to found the keywords ending in state. The state must be
// premultiplied.
func (idx *keywordIndex) collect(state uint32, found bitset) {
	for _, id := range idx.outputs[state>>8] {
		found.add(id)
	}
}

// hasKeyword reports whether the rule at position n has one of its keywords in
// found. A rule with a nil mask always does, and so does every rule when there
// is no index or when n is past the rules the index was built for.
func (idx *keywordIndex) hasKeyword(n int, found bitset) bool {
	if idx == nil || n >= len(idx.ruleMasks) {
		return true
	}
	mask := idx.ruleMasks[n]
	return mask == nil || found.intersects(mask)
}

// foldASCII lowercases an ASCII letter and leaves any other byte alone.
func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// foldASCIIString folds every byte of s.
func foldASCIIString(s string) string {
	folded := []byte(s)
	for i, c := range folded {
		folded[i] = foldASCII(c)
	}
	return string(folded)
}

// bitset is a set of keyword ids, packed 64 to a word.
type bitset []uint64

func newBitset(n int) bitset {
	return make(bitset, (n+63)/64)
}

func (b bitset) add(id int32) {
	b[id/64] |= 1 << (uint32(id) % 64)
}

// intersects reports whether b and other share an id. Both must have been
// built for the same number of keywords.
func (b bitset) intersects(other bitset) bool {
	for i, word := range other {
		if b[i]&word != 0 {
			return true
		}
	}
	return false
}
