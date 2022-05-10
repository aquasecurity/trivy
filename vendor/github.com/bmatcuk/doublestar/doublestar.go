package doublestar

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// An OS abstracts functions in the standard library's os package.
type OS interface {
	Lstat(name string) (os.FileInfo, error)
	Open(name string) (*os.File, error)
	PathSeparator() rune
	Stat(name string) (os.FileInfo, error)
}

// StandardOS is a value that implements the OS interface by calling functions
// in the standard libray's os package.
var StandardOS OS = standardOS{}

// A standardOS implements OS by calling functions in the standard library's os
// package.
type standardOS struct{}

func (standardOS) Lstat(name string) (os.FileInfo, error) { return os.Lstat(name) }
func (standardOS) Open(name string) (*os.File, error)     { return os.Open(name) }
func (standardOS) PathSeparator() rune                    { return os.PathSeparator }
func (standardOS) Stat(name string) (os.FileInfo, error)  { return os.Stat(name) }

// ErrBadPattern indicates a pattern was malformed.
var ErrBadPattern = path.ErrBadPattern

// Split a path on the given separator, respecting escaping.
func splitPathOnSeparator(path string, separator rune) (ret []string) {
	idx := 0
	if separator == '\\' {
		// if the separator is '\\', then we can just split...
		ret = strings.Split(path, string(separator))
		idx = len(ret)
	} else {
		// otherwise, we need to be careful of situations where the separator was escaped
		cnt := strings.Count(path, string(separator))
		if cnt == 0 {
			return []string{path}
		}

		ret = make([]string, cnt+1)
		pathlen := len(path)
		separatorLen := utf8.RuneLen(separator)
		emptyEnd := false
		for start := 0; start < pathlen; {
			end := indexRuneWithEscaping(path[start:], separator)
			if end == -1 {
				emptyEnd = false
				end = pathlen
			} else {
				emptyEnd = true
				end += start
			}
			ret[idx] = path[start:end]
			start = end + separatorLen
			idx++
		}

		// If the last rune is a path separator, we need to append an empty string to
		// represent the last, empty path component. By default, the strings from
		// make([]string, ...) will be empty, so we just need to icrement the count
		if emptyEnd {
			idx++
		}
	}

	return ret[:idx]
}

// Find the first index of a rune in a string,
// ignoring any times the rune is escaped using "\".
func indexRuneWithEscaping(s string, r rune) int {
	end := strings.IndexRune(s, r)
	if end == -1 {
		return -1
	}
	if end > 0 && s[end-1] == '\\' {
		start := end + utf8.RuneLen(r)
		end = indexRuneWithEscaping(s[start:], r)
		if end != -1 {
			end += start
		}
	}
	return end
}

// Find the last index of a rune in a string,
// ignoring any times the rune is escaped using "\".
func lastIndexRuneWithEscaping(s string, r rune) int {
	end := strings.LastIndex(s, string(r))
	if end == -1 {
		return -1
	}
	if end > 0 && s[end-1] == '\\' {
		end = lastIndexRuneWithEscaping(s[:end-1], r)
	}
	return end
}

// Find the index of the first instance of one of the unicode characters in
// chars, ignoring any times those characters are escaped using "\".
func indexAnyWithEscaping(s, chars string) int {
	end := strings.IndexAny(s, chars)
	if end == -1 {
		return -1
	}
	if end > 0 && s[end-1] == '\\' {
		_, adj := utf8.DecodeRuneInString(s[end:])
		start := end + adj
		end = indexAnyWithEscaping(s[start:], chars)
		if end != -1 {
			end += start
		}
	}
	return end
}

// Split a set of alternatives such as {alt1,alt2,...} and returns the index of
// the rune after the closing curly brace. Respects nested alternatives and
// escaped runes.
func splitAlternatives(s string) (ret []string, idx int) {
	ret = make([]string, 0, 2)
	idx = 0
	slen := len(s)
	braceCnt := 1
	esc := false
	start := 0
	for braceCnt > 0 {
		if idx >= slen {
			return nil, -1
		}

		sRune, adj := utf8.DecodeRuneInString(s[idx:])
		if esc {
			esc = false
		} else if sRune == '\\' {
			esc = true
		} else if sRune == '{' {
			braceCnt++
		} else if sRune == '}' {
			braceCnt--
		} else if sRune == ',' && braceCnt == 1 {
			ret = append(ret, s[start:idx])
			start = idx + adj
		}

		idx += adj
	}
	ret = append(ret, s[start:idx-1])
	return
}

// Returns true if the pattern is "zero length", meaning
// it could match zero or more characters.
func isZeroLengthPattern(pattern string) (ret bool, err error) {
	// * can match zero
	if pattern == "" || pattern == "*" || pattern == "**" {
		return true, nil
	}

	// an alternative with zero length can match zero, for example {,x} - the
	// first alternative has zero length
	r, adj := utf8.DecodeRuneInString(pattern)
	if r == '{' {
		options, endOptions := splitAlternatives(pattern[adj:])
		if endOptions == -1 {
			return false, ErrBadPattern
		}
		if ret, err = isZeroLengthPattern(pattern[adj+endOptions:]); !ret || err != nil {
			return
		}
		for _, o := range options {
			if ret, err = isZeroLengthPattern(o); ret || err != nil {
				return
			}
		}
	}

	return false, nil
}

// Match returns true if name matches the shell file name pattern.
// The pattern syntax is:
//
//  pattern:
//    { term }
//  term:
//    '*'         matches any sequence of non-path-separators
//    '**'        matches any sequence of characters, including
//                path separators.
//    '?'         matches any single non-path-separator character
//    '[' [ '^' ] { character-range } ']'
//          character class (must be non-empty)
//    '{' { term } [ ',' { term } ... ] '}'
//    c           matches character c (c != '*', '?', '\\', '[')
//    '\\' c      matches character c
//
//  character-range:
//    c           matches character c (c != '\\', '-', ']')
//    '\\' c      matches character c
//    lo '-' hi   matches character c for lo <= c <= hi
//
// Match requires pattern to match all of name, not just a substring.
// The path-separator defaults to the '/' character. The only possible
// returned error is ErrBadPattern, when pattern is malformed.
//
// Note: this is meant as a drop-in replacement for path.Match() which
// always uses '/' as the path separator. If you want to support systems
// which use a different path separator (such as Windows), what you want
// is the PathMatch() function below.
//
func Match(pattern, name string) (bool, error) {
	return matchWithSeparator(pattern, name, '/')
}

// PathMatch is like Match except that it uses your system's path separator.
// For most systems, this will be '/'. However, for Windows, it would be '\\'.
// Note that for systems where the path separator is '\\', escaping is
// disabled.
//
// Note: this is meant as a drop-in replacement for filepath.Match().
//
func PathMatch(pattern, name string) (bool, error) {
	return PathMatchOS(StandardOS, pattern, name)
}

// PathMatchOS is like PathMatch except that it uses vos's path separator.
func PathMatchOS(vos OS, pattern, name string) (bool, error) {
	pattern = filepath.ToSlash(pattern)
	return matchWithSeparator(pattern, name, vos.PathSeparator())
}

// Match returns true if name matches the shell file name pattern.
// The pattern syntax is:
//
//  pattern:
//    { term }
//  term:
//    '*'         matches any sequence of non-path-separators
//              '**'        matches any sequence of characters, including
//                          path separators.
//    '?'         matches any single non-path-separator character
//    '[' [ '^' ] { character-range } ']'
//          character class (must be non-empty)
//    '{' { term } [ ',' { term } ... ] '}'
//    c           matches character c (c != '*', '?', '\\', '[')
//    '\\' c      matches character c
//
//  character-range:
//    c           matches character c (c != '\\', '-', ']')
//    '\\' c      matches character c, unless separator is '\\'
//    lo '-' hi   matches character c for lo <= c <= hi
//
// Match requires pattern to match all of name, not just a substring.
// The only possible returned error is ErrBadPattern, when pattern
// is malformed.
//
func matchWithSeparator(pattern, name string, separator rune) (bool, error) {
	nameComponents := splitPathOnSeparator(name, separator)
	return doMatching(pattern, nameComponents)
}

func doMatching(pattern string, nameComponents []string) (matched bool, err error) {
	// check for some base-cases
	patternLen, nameLen := len(pattern), len(nameComponents)
	if patternLen == 0 && nameLen == 0 {
		return true, nil
	}
	if patternLen == 0 {
		if nameLen == 1 && nameComponents[0] == "" {
			return true, nil
		} else if nameLen == 0 {
			return false, nil
		}
	}

	slashIdx := indexRuneWithEscaping(pattern, '/')
	lastComponent := slashIdx == -1
	if lastComponent {
		slashIdx = len(pattern)
	}
	if pattern[:slashIdx] == "**" {
		// if our last pattern component is a doublestar, we're done -
		// doublestar will match any remaining name components, if any.
		if lastComponent {
			return true, nil
		}

		// otherwise, try matching remaining components
		for nameIdx := 0; nameIdx < nameLen; nameIdx++ {
			if m, _ := doMatching(pattern[slashIdx+1:], nameComponents[nameIdx:]); m {
				return true, nil
			}
		}
		return false, nil
	}

	var matches []string
	matches, err = matchComponent(pattern, nameComponents[0])
	if matches == nil || err != nil {
		return
	}
	if len(matches) == 0 && nameLen == 1 {
		return true, nil
	}

	if nameLen > 1 {
		for _, alt := range matches {
			matched, err = doMatching(alt, nameComponents[1:])
			if matched || err != nil {
				return
			}
		}
	}

	return false, nil
}

// Glob returns the names of all files matching pattern or nil
// if there is no matching file. The syntax of pattern is the same
// as in Match. The pattern may describe hierarchical names such as
// /usr/*/bin/ed (assuming the Separator is '/').
//
// Glob ignores file system errors such as I/O errors reading directories.
// The only possible returned error is ErrBadPattern, when pattern
// is malformed.
//
// Your system path separator is automatically used. This means on
// systems where the separator is '\\' (Windows), escaping will be
// disabled.
//
// Note: this is meant as a drop-in replacement for filepath.Glob().
//
func Glob(pattern string) (matches []string, err error) {
	return GlobOS(StandardOS, pattern)
}

// GlobOS is like Glob except that it operates on vos.
func GlobOS(vos OS, pattern string) (matches []string, err error) {
	if len(pattern) == 0 {
		return nil, nil
	}

	// if the pattern starts with alternatives, we need to handle that here - the
	// alternatives may be a mix of relative and absolute
	if pattern[0] == '{' {
		options, endOptions := splitAlternatives(pattern[1:])
		if endOptions == -1 {
			return nil, ErrBadPattern
		}
		for _, o := range options {
			m, e := GlobOS(vos, o+pattern[endOptions+1:])
			if e != nil {
				return nil, e
			}
			matches = append(matches, m...)
		}
		return matches, nil
	}

	// If the pattern is relative or absolute and we're on a non-Windows machine,
	// volumeName will be an empty string. If it is absolute and we're on a
	// Windows machine, volumeName will be a drive letter ("C:") for filesystem
	// paths or \\<server>\<share> for UNC paths.
	isAbs := filepath.IsAbs(pattern) || pattern[0] == '\\' || pattern[0] == '/'
	volumeName := filepath.VolumeName(pattern)
	isWindowsUNC := strings.HasPrefix(volumeName, `\\`)
	if isWindowsUNC || isAbs {
		startIdx := len(volumeName) + 1
		return doGlob(vos, fmt.Sprintf("%s%s", volumeName, string(vos.PathSeparator())), filepath.ToSlash(pattern[startIdx:]), matches)
	}

	// otherwise, it's a relative pattern
	return doGlob(vos, ".", filepath.ToSlash(pattern), matches)
}

// Perform a glob
func doGlob(vos OS, basedir, pattern string, matches []string) (m []string, e error) {
	m = matches
	e = nil

	// if the pattern starts with any path components that aren't globbed (ie,
	// `path/to/glob*`), we can skip over the un-globbed components (`path/to` in
	// our example).
	globIdx := indexAnyWithEscaping(pattern, "*?[{\\")
	if globIdx > 0 {
		globIdx = lastIndexRuneWithEscaping(pattern[:globIdx], '/')
	} else if globIdx == -1 {
		globIdx = lastIndexRuneWithEscaping(pattern, '/')
	}
	if globIdx > 0 {
		basedir = filepath.Join(basedir, pattern[:globIdx])
		pattern = pattern[globIdx+1:]
	}

	// Lstat will return an error if the file/directory doesn't exist
	fi, err := vos.Lstat(basedir)
	if err != nil {
		return
	}

	// if the pattern is empty, we've found a match
	if len(pattern) == 0 {
		m = append(m, basedir)
		return
	}

	// otherwise, we need to check each item in the directory...

	// first, if basedir is a symlink, follow it...
	if (fi.Mode() & os.ModeSymlink) != 0 {
		fi, err = vos.Stat(basedir)
		if err != nil {
			return
		}
	}

	// confirm it's a directory...
	if !fi.IsDir() {
		return
	}

	files, err := filesInDir(vos, basedir)
	if err != nil {
		return
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })

	slashIdx := indexRuneWithEscaping(pattern, '/')
	lastComponent := slashIdx == -1
	if lastComponent {
		slashIdx = len(pattern)
	}
	if pattern[:slashIdx] == "**" {
		// if the current component is a doublestar, we'll try depth-first
		for _, file := range files {
			// if symlink, we may want to follow
			if (file.Mode() & os.ModeSymlink) != 0 {
				file, err = vos.Stat(filepath.Join(basedir, file.Name()))
				if err != nil {
					continue
				}
			}

			if file.IsDir() {
				// recurse into directories
				if lastComponent {
					m = append(m, filepath.Join(basedir, file.Name()))
				}
				m, e = doGlob(vos, filepath.Join(basedir, file.Name()), pattern, m)
			} else if lastComponent {
				// if the pattern's last component is a doublestar, we match filenames, too
				m = append(m, filepath.Join(basedir, file.Name()))
			}
		}
		if lastComponent {
			return // we're done
		}

		pattern = pattern[slashIdx+1:]
	}

	// check items in current directory and recurse
	var match []string
	for _, file := range files {
		match, e = matchComponent(pattern, file.Name())
		if e != nil {
			return
		}
		if match != nil {
			if len(match) == 0 {
				m = append(m, filepath.Join(basedir, file.Name()))
			} else {
				for _, alt := range match {
					m, e = doGlob(vos, filepath.Join(basedir, file.Name()), alt, m)
				}
			}
		}
	}
	return
}

func filesInDir(vos OS, dirPath string) (files []os.FileInfo, e error) {
	dir, err := vos.Open(dirPath)
	if err != nil {
		return nil, nil
	}
	defer func() {
		if err := dir.Close(); e == nil {
			e = err
		}
	}()

	files, err = dir.Readdir(-1)
	if err != nil {
		return nil, nil
	}

	return
}

// Attempt to match a single path component with a pattern. Note that the
// pattern may include multiple components but that the "name" is just a single
// path component. The return value is a slice of patterns that should be
// checked against subsequent path components or nil, indicating that the
// pattern does not match this path. It is assumed that pattern components are
// separated by '/'
func matchComponent(pattern, name string) ([]string, error) {
	// check for matches one rune at a time
	patternLen, nameLen := len(pattern), len(name)
	patIdx, nameIdx := 0, 0
	for patIdx < patternLen && nameIdx < nameLen {
		patRune, patAdj := utf8.DecodeRuneInString(pattern[patIdx:])
		nameRune, nameAdj := utf8.DecodeRuneInString(name[nameIdx:])
		if patRune == '/' {
			patIdx++
			break
		} else if patRune == '\\' {
			// handle escaped runes, only if separator isn't '\\'
			patIdx += patAdj
			patRune, patAdj = utf8.DecodeRuneInString(pattern[patIdx:])
			if patRune == utf8.RuneError {
				return nil, ErrBadPattern
			} else if patRune == nameRune {
				patIdx += patAdj
				nameIdx += nameAdj
			} else {
				return nil, nil
			}
		} else if patRune == '*' {
			// handle stars - a star at the end of the pattern or before a separator
			// will always match the rest of the path component
			if patIdx += patAdj; patIdx >= patternLen {
				return []string{}, nil
			}
			if patRune, patAdj = utf8.DecodeRuneInString(pattern[patIdx:]); patRune == '/' {
				return []string{pattern[patIdx+patAdj:]}, nil
			}

			// check if we can make any matches
			for ; nameIdx < nameLen; nameIdx += nameAdj {
				if m, e := matchComponent(pattern[patIdx:], name[nameIdx:]); m != nil || e != nil {
					return m, e
				}
				_, nameAdj = utf8.DecodeRuneInString(name[nameIdx:])
			}
			return nil, nil
		} else if patRune == '[' {
			// handle character sets
			patIdx += patAdj
			endClass := indexRuneWithEscaping(pattern[patIdx:], ']')
			if endClass == -1 {
				return nil, ErrBadPattern
			}
			endClass += patIdx
			classRunes := []rune(pattern[patIdx:endClass])
			classRunesLen := len(classRunes)
			if classRunesLen > 0 {
				classIdx := 0
				matchClass := false
				if classRunes[0] == '^' {
					classIdx++
				}
				for classIdx < classRunesLen {
					low := classRunes[classIdx]
					if low == '-' {
						return nil, ErrBadPattern
					}
					classIdx++
					if low == '\\' {
						if classIdx < classRunesLen {
							low = classRunes[classIdx]
							classIdx++
						} else {
							return nil, ErrBadPattern
						}
					}
					high := low
					if classIdx < classRunesLen && classRunes[classIdx] == '-' {
						// we have a range of runes
						if classIdx++; classIdx >= classRunesLen {
							return nil, ErrBadPattern
						}
						high = classRunes[classIdx]
						if high == '-' {
							return nil, ErrBadPattern
						}
						classIdx++
						if high == '\\' {
							if classIdx < classRunesLen {
								high = classRunes[classIdx]
								classIdx++
							} else {
								return nil, ErrBadPattern
							}
						}
					}
					if low <= nameRune && nameRune <= high {
						matchClass = true
					}
				}
				if matchClass == (classRunes[0] == '^') {
					return nil, nil
				}
			} else {
				return nil, ErrBadPattern
			}
			patIdx = endClass + 1
			nameIdx += nameAdj
		} else if patRune == '{' {
			// handle alternatives such as {alt1,alt2,...}
			patIdx += patAdj
			options, endOptions := splitAlternatives(pattern[patIdx:])
			if endOptions == -1 {
				return nil, ErrBadPattern
			}
			patIdx += endOptions

			results := make([][]string, 0, len(options))
			totalResults := 0
			for _, o := range options {
				m, e := matchComponent(o+pattern[patIdx:], name[nameIdx:])
				if e != nil {
					return nil, e
				}
				if m != nil {
					results = append(results, m)
					totalResults += len(m)
				}
			}
			if len(results) > 0 {
				lst := make([]string, 0, totalResults)
				for _, m := range results {
					lst = append(lst, m...)
				}
				return lst, nil
			}

			return nil, nil
		} else if patRune == '?' || patRune == nameRune {
			// handle single-rune wildcard
			patIdx += patAdj
			nameIdx += nameAdj
		} else {
			return nil, nil
		}
	}
	if nameIdx >= nameLen {
		if patIdx >= patternLen {
			return []string{}, nil
		}

		pattern = pattern[patIdx:]
		slashIdx := indexRuneWithEscaping(pattern, '/')
		testPattern := pattern
		if slashIdx >= 0 {
			testPattern = pattern[:slashIdx]
		}

		zeroLength, err := isZeroLengthPattern(testPattern)
		if err != nil {
			return nil, err
		}
		if zeroLength {
			if slashIdx == -1 {
				return []string{}, nil
			} else {
				return []string{pattern[slashIdx+1:]}, nil
			}
		}
	}
	return nil, nil
}
