package lcss

import "bytes"

// LongestCommonSubstring returns the longest substring which is present in all the given strings.
// https://en.wikipedia.org/wiki/Longest_common_substring_problem
// Not to be confused with the Longest Common Subsequence.
// Complexity:
// * time: sum of `n_i*log(n_i)` where `n_i` is the length of each string.
// * space: sum of `n_i`.
// Returns a byte slice which is never a nil.
//
// ### Algorithm.
// We build suffix arrays for each of the passed string and then follow the same procedure
// as in merge sort: pick the least suffix in the lexicographical order. It is possible
// because the suffix arrays are already sorted.
// We record the last encountered suffixes from each of the strings and measure the longest
// common prefix of those at each "merge sort" step.
// The string comparisons are optimized by maintaining the char-level prefix tree of the "heads"
// of the suffix array sequences.
func LongestCommonSubstring(strs ...[]byte) []byte {
	strslen := len(strs)
	if strslen == 0 {
		return []byte{}
	}
	if strslen == 1 {
		return strs[0]
	}
	suffixes := make([][]int, strslen)
	for i, str := range strs {
		suffixes[i] = qsufsort(str)
	}
	return lcss(strs, suffixes)
}

func lcss(strs [][]byte, suffixes [][]int) []byte {
	strslen := len(strs)
	if strslen == 0 {
		return []byte{}
	}
	if strslen == 1 {
		return strs[0]
	}
	minstrlen := len(strs[0]) // minimum length of the strings
	for _, str := range strs {
		if minstrlen > len(str) {
			minstrlen = len(str)
		}
	}
	heads := make([]int, strslen)          // position in each suffix array
	boilerplate := make([][]byte, strslen) // existing suffixes in the tree
	boiling := 0                           // indicates how many distinct suffix arrays are presented in `boilerplate`
	var root charNode                      // the character tree built on the strings from `boilerplate`
	lcs := []byte{}                        // our function's return value, `var lcss []byte` does *not* work
	for {
		mini := -1
		var minSuffixStr []byte
		for i, head := range heads {
			if head >= len(suffixes[i]) {
				// this suffix array has been scanned till the end
				continue
			}
			suffix := strs[i][suffixes[i][head]:]
			if minSuffixStr == nil {
				// initialize
				mini = i
				minSuffixStr = suffix
			} else if bytes.Compare(minSuffixStr, suffix) > 0 {
				// the current suffix is the smallest in the lexicographical order
				mini = i
				minSuffixStr = suffix
			}
		}
		if mini == -1 {
			// all heads exhausted
			break
		}
		if boilerplate[mini] != nil {
			// if we already have a suffix from this string, replace it with the new one
			root.Remove(boilerplate[mini])
		} else {
			// we track the number of distinct strings which have been touched
			// when `boiling` becomes strslen we can start measuring the longest common prefix
			boiling++
		}
		boilerplate[mini] = minSuffixStr
		root.Add(minSuffixStr)
		heads[mini]++
		if boiling == strslen && root.LongestCommonPrefixLength() > len(lcs) {
			// all heads > 0, the current common prefix of the suffixes is the longest
			lcs = root.LongestCommonPrefix()
			if len(lcs) == minstrlen {
				// early exit - we will never find a longer substring
				break
			}
		}
	}
	return lcs
}

// charNode builds a tree of individual characters.
// `used` is the counter for collecting garbage: those nodes which have `used`=0 are removed.
// The root charNode always remains intact apart from `children`.
// The tree supports 4 operations:
// 1. Add() a new string.
// 2. Remove() an existing string which was previously Add()-ed.
// 3. LongestCommonPrefixLength().
// 4. LongestCommonPrefix().
type charNode struct {
	char     byte
	children []charNode
	used     int
}

// Add includes a new string into the tree. We start from the root and
// increment `used` of all the nodes we visit.
func (cn *charNode) Add(str []byte) {
	head := cn
	for i, char := range str {
		found := false
		for j, child := range head.children {
			if child.char == char {
				head.children[j].used++
				head = &head.children[j] // -> child
				found = true
				break
			}
		}
		if !found {
			// add the missing nodes one by one
			for _, char = range str[i:] {
				head.children = append(head.children, charNode{char: char, children: nil, used: 1})
				head = &head.children[len(head.children)-1]
			}
			break
		}
	}
}

// Remove excludes a node which was previously Add()-ed.
// We start from the root and decrement `used` of all the nodes we visit.
// If there is a node with `used`=0, we erase it from the parent's list of children
// and stop traversing the tree.
func (cn *charNode) Remove(str []byte) {
	stop := false
	head := cn
	for _, char := range str {
		for j, child := range head.children {
			if child.char != char {
				continue
			}
			head.children[j].used--
			var parent *charNode
			head, parent = &head.children[j], head // shift to the child
			if head.used == 0 {
				parent.children = append(parent.children[:j], parent.children[j+1:]...)
				// we can skip deleting the rest of the nodes - they have been already discarded
				stop = true
			}
			break
		}
		if stop {
			break
		}
	}
}

// LongestCommonPrefixLength returns the length of the longest common prefix of the strings
// which are stored in the tree. We visit the children recursively starting from the root and
// stop if `used` value decreases or there is more than one child.
func (cn charNode) LongestCommonPrefixLength() int {
	var result int
	for head := cn; len(head.children) == 1 && head.children[0].used >= head.used; head = head.children[0] {

		result++
	}
	return result
}

// LongestCommonPrefix returns the longest common prefix of the strings
// which are stored in the tree. We compute the length by calling LongestCommonPrefixLength()
// and then record the characters which we visit along the way from the root to the last node.
func (cn charNode) LongestCommonPrefix() []byte {
	result := make([]byte, cn.LongestCommonPrefixLength())
	if len(result) == 0 {
		return result
	}
	var i int
	for head := cn.children[0]; ; head = head.children[0] {
		result[i] = head.char
		i++
		if i == len(result) {
			break
		}
	}
	return result
}
