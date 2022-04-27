# doublestar

Path pattern matching and globbing supporting `doublestar` (`**`) patterns.

![Release](https://img.shields.io/github/release/bmatcuk/doublestar.svg?branch=master)
[![Build Status](https://travis-ci.org/bmatcuk/doublestar.svg?branch=master)](https://travis-ci.org/bmatcuk/doublestar)
[![codecov.io](https://img.shields.io/codecov/c/github/bmatcuk/doublestar.svg?branch=master)](https://codecov.io/github/bmatcuk/doublestar?branch=master)

## About

**doublestar** is a [golang](http://golang.org/) implementation of path pattern
matching and globbing with support for "doublestar" (aka globstar: `**`)
patterns.

doublestar patterns match files and directories recursively. For example, if
you had the following directory structure:

```bash
grandparent
`-- parent
    |-- child1
    `-- child2
```

You could find the children with patterns such as: `**/child*`,
`grandparent/**/child?`, `**/parent/*`, or even just `**` by itself (which will
return all files and directories recursively).

Bash's globstar is doublestar's inspiration and, as such, works similarly.
Note that the doublestar must appear as a path component by itself. A pattern
such as `/path**` is invalid and will be treated the same as `/path*`, but
`/path*/**` should achieve the desired result. Additionally, `/path/**` will
match all directories and files under the path directory, but `/path/**/` will
only match directories.

## Installation

**doublestar** can be installed via `go get`:

```bash
go get github.com/bmatcuk/doublestar
```

To use it in your code, you must import it:

```go
import "github.com/bmatcuk/doublestar"
```

## Usage

### Match

```go
func Match(pattern, name string) (bool, error)
```

Match returns true if `name` matches the file name `pattern`
([see below](#patterns)). `name` and `pattern` are split on forward slash (`/`)
characters and may be relative or absolute.

Note: `Match()` is meant to be a drop-in replacement for `path.Match()`. As
such, it always uses `/` as the path separator. If you are writing code that
will run on systems where `/` is not the path separator (such as Windows), you
want to use `PathMatch()` (below) instead.


### PathMatch

```go
func PathMatch(pattern, name string) (bool, error)
```

PathMatch returns true if `name` matches the file name `pattern`
([see below](#patterns)). The difference between Match and PathMatch is that
PathMatch will automatically use your system's path separator to split `name`
and `pattern`.

`PathMatch()` is meant to be a drop-in replacement for `filepath.Match()`.

### Glob

```go
func Glob(pattern string) ([]string, error)
```

Glob finds all files and directories in the filesystem that match `pattern`
([see below](#patterns)). `pattern` may be relative (to the current working
directory), or absolute.

`Glob()` is meant to be a drop-in replacement for `filepath.Glob()`.

### Patterns

**doublestar** supports the following special terms in the patterns:

Special Terms | Meaning
------------- | -------
`*`           | matches any sequence of non-path-separators
`**`          | matches any sequence of characters, including path separators
`?`           | matches any single non-path-separator character
`[class]`     | matches any single non-path-separator character against a class of characters ([see below](#character-classes))
`{alt1,...}`  | matches a sequence of characters if one of the comma-separated alternatives matches

Any character with a special meaning can be escaped with a backslash (`\`).

#### Character Classes

Character classes support the following:

Class      | Meaning
---------- | -------
`[abc]`    | matches any single character within the set
`[a-z]`    | matches any single character in the range
`[^class]` | matches any single character which does *not* match the class

### Abstracting the `os` package

**doublestar** by default uses the `Open`, `Stat`, and `Lstat`, functions and
`PathSeparator` value from the standard library's `os` package. To abstract
this, for example to be able to perform tests of Windows paths on Linux, or to
interoperate with your own filesystem code, it includes the functions `GlobOS`
and `PathMatchOS` which are identical to `Glob` and `PathMatch` except that they
operate on an `OS` interface:

```go
type OS interface {
    Lstat(name string) (os.FileInfo, error)
    Open(name string) (*os.File, error)
    PathSeparator() rune
    Stat(name string) (os.FileInfo, error)
}
```

`StandardOS` is a value that implements this interface by calling functions in
the standard library's `os` package.

## License

[MIT License](LICENSE)
