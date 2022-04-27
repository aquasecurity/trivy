package version

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode"
)

type parts int

const (
	tokenInvalid parts = iota - 1
	tokenDigitOrZero
	tokenDigit
	tokenLetter
	tokenSuffix
	tokenSuffixNo
	tokenRevisionNo
	tokenEnd
)

// Version represents a package version
// ref. https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/master/src/version.c
type Version string

type version bufio.Reader

// NewVersion returns a parsed version
func NewVersion(ver string) (Version, error) {
	if !Valid(ver) {
		// Even if a version is invalid, a caller needs to be able to do sort.
		return Version(ver), errors.New("invalid version")
	}
	return Version(ver), nil
}

func newVersion(ver string) version {
	s := strings.NewReader(ver)
	b := bufio.NewReader(s)
	return version(*b)
}

func (v1 *version) nextToken(tokenType parts) parts {
	n := tokenInvalid

	v := (*bufio.Reader)(v1)
	r, size, err := v.ReadRune()
	if size == 0 && err != nil {
		if err != io.EOF {
			return tokenInvalid
		}
		n = tokenEnd
	}

	if (tokenType == tokenDigit || tokenType == tokenDigitOrZero) && unicode.IsLower(r) {
		n = tokenLetter
	} else if tokenType == tokenLetter && unicode.IsDigit(r) {
		n = tokenDigit
	} else if tokenType == tokenSuffix && unicode.IsDigit(r) {
		n = tokenSuffixNo
	} else {
		switch r {
		case '.':
			n = tokenDigitOrZero
		case '_':
			n = tokenSuffix
		case '-':
			r, size, err = v.ReadRune()
			if size == 0 && err == io.EOF {
				n = tokenInvalid
			} else {
				n = tokenRevisionNo
			}
		}
	}

	if n == tokenEnd || n == tokenLetter || n == tokenDigit || n == tokenSuffixNo {
		_ = v.UnreadRune()
	}

	if n < tokenType {
		switch {
		case n == tokenDigitOrZero && tokenType == tokenDigit:
			return n
		case n == tokenSuffix && tokenType == tokenSuffixNo:
			return n
		case n == tokenDigit && tokenType == tokenLetter:
			return n
		default:
			return tokenInvalid
		}
	}

	return n
}

var (
	preSuffixes  = [4]string{"alpha", "beta", "pre", "rc"}
	postSuffixes = [5]string{"cvs", "svn", "git", "hg", "p"}
)

func (v1 *version) getToken(tokenType parts) (int, parts, error) {
	nt := tokenInvalid
	var value int

	v := (*bufio.Reader)(v1)
	r, size, err := v.ReadRune()
	if size == 0 && err != nil && err != io.EOF {
		return 0, tokenType, err
	}

	switch tokenType {
	case tokenDigitOrZero:
		/* Leading zero digits get a special treatment */
		if r == '0' {
			for {
				value -= 1

				r, size, err := v.ReadRune()
				if err != nil && err != io.EOF {
					return 0, tokenType, err
				}

				if size == 0 && err == io.EOF {
					break
				}

				if r != '0' {
					_ = v.UnreadRune()
					break
				}
			}
			nt = tokenDigit
			break
		}
		fallthrough
	case tokenDigit, tokenSuffixNo, tokenRevisionNo:
		for unicode.IsDigit(r) {
			value *= 10
			value += int(r - '0')

			r, size, err = v.ReadRune()
			if err != nil && err != io.EOF {
				return 0, tokenType, err
			}

			if size == 0 && err == io.EOF {
				break
			}
		}
		_ = v.UnreadRune()
	case tokenLetter:
		value = int(r)
	case tokenSuffix:
		_ = v.UnreadRune()
		for i, s := range preSuffixes {
			b, err := v.Peek(len(s))
			if err != nil && err != io.EOF {
				return 0, tokenType, err
			}
			if string(b) == s {
				value = i - len(preSuffixes)
				_, _ = v.Discard(len(s))
				break
			}
		}
		if value != 0 {
			break
		}

		value = -1
		for i, s := range postSuffixes {
			b, err := v.Peek(len(s))
			if err != nil && err != io.EOF {
				return 0, tokenType, err
			}
			if string(b) == s {
				value = i
				_, _ = v.Discard(len(s))
				break
			}
		}
		if value >= 0 {
			break
		}

		/* fallthrough: invalid suffix */
		fallthrough
	default:
		tokenType = tokenInvalid
		return -1, tokenType, nil
	}

	if _, err = v.Peek(1); err == io.EOF {
		tokenType = tokenEnd
	} else if nt != tokenInvalid {
		tokenType = nt
	} else {
		tokenType = v1.nextToken(tokenType)
	}

	return value, tokenType, nil
}

const (
	apkVersionEqual   = 0
	apkVersionLess    = -1
	apkVersionGreater = 1
)

// Valid validates the version
func Valid(ver string) bool {
	t := tokenDigit

	v := newVersion(ver)
	for t != tokenEnd && t != tokenInvalid {
		_, t, _ = v.getToken(t)
	}

	return t == tokenEnd
}

// Equal returns whether this version is equal with another version.
func (v1 *Version) Equal(v2 Version) bool {
	return v1.Compare(v2) == 0
}

// GreaterThan returns whether this version is greater than another version.
func (v1 *Version) GreaterThan(v2 Version) bool {
	return v1.Compare(v2) > 0
}

// LessThan returns whether this version is less than another version.
func (v1 Version) LessThan(v2 Version) bool {
	return v1.Compare(v2) < 0
}

// Compare returns an integer comparing two version according to apk version.
// The result will be 0 if v1==v2, -1 if v1 < v2, and +1 if v1 > v2.
func (v1 Version) Compare(v2 Version) int {
	return compare(v1, v2)
}

func compare(ver1, ver2 Version) int {
	v1 := newVersion(string(ver1))
	v2 := newVersion(string(ver2))

	at := tokenDigit
	bt := tokenDigit

	var av, bv int

	for at == bt && at != tokenEnd && at != tokenInvalid && av == bv {
		// err is not supposed to happen
		av, at, _ = v1.getToken(at)
		bv, bt, _ = v2.getToken(bt)
	}

	/* value of this token differs? */
	if av < bv {
		return apkVersionLess
	} else if av > bv {
		return apkVersionGreater
	}

	/* both have TOKEN_END or TOKEN_INVALID next? */
	if at == bt {
		return apkVersionEqual
	}

	/* leading version components and their values are equal,
	 * now the non-terminating version is greater unless it's a suffix
	 * indicating pre-release */
	if at == tokenSuffix {
		v, _, _ := v1.getToken(at)
		if v < 0 {
			return apkVersionLess
		}
	}

	if bt == tokenSuffix {
		v, _, err := v2.getToken(bt)
		if err != nil {
			return 0
		}
		if v < 0 {
			return apkVersionGreater
		}
	}

	if at > bt {
		return apkVersionLess
	} else if at < bt {
		return apkVersionGreater
	}
	return apkVersionEqual
}
