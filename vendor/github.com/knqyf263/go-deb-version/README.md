# go-deb-version

[![Build Status](https://travis-ci.org/knqyf263/go-deb-version.svg?branch=master)](https://travis-ci.org/knqyf263/go-deb-version)
[![Coverage Status](https://coveralls.io/repos/github/knqyf263/go-deb-version/badge.svg)](https://coveralls.io/github/knqyf263/go-deb-version)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/go-deb-version)](https://goreportcard.com/report/github.com/knqyf263/go-deb-version)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/knqyf263/go-deb-version/blob/master/LICENSE)

A Go library for parsing package versions

go-deb-version is a library for parsing and comparing versions

Versions used with go-deb-version must follow [deb-version](http://man.he.net/man5/deb-version) (ex. 2:6.0-9ubuntu1)  
The implementation is based on [Debian Policy Manual](https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version)

OS: Debian, Ubnutu


# Installation and Usage

Installation can be done with a normal go get:

```
$ go get github.com/knqyf263/go-deb-version
```

## Version Parsing and Comparison

```
import "github.com/knqyf263/go-deb-version"

v1, err := version.NewVersion("2:6.0-9")
v2, err := version.NewVersion("2:6.0-9ubuntu1")

// Comparison example. There is also GreaterThan, Equal.
if v1.LessThan(v2) {
    fmt.Printf("%s is less than %s", v1, v2)
}
```

## Version Sorting

```
raw := []string{"7.4.052-1ubuntu3.1", "7.4.052-1ubuntu3", "7.1-022+1ubuntu1", "7.1.291-1", "7.3.000+hg~ee53a39d5896-1"}
vs := make([]version.Version, len(raw))
for i, r := range raw {
	v, _ := version.NewVersion(r)
	vs[i] = v
}

sort.Slice(vs, func(i, j int) bool {
	return vs[i].LessThan(vs[j])
})
```

# Contribute

1. fork a repository: github.com/knqyf263/go-deb-version to github.com/you/repo
2. get original code: `go get github.com/knqyf263/go-deb-version`
3. work on original code
4. add remote to your repo: git remote add myfork https://github.com/you/repo.git
5. push your changes: git push myfork
6. create a new Pull Request

- see [GitHub and Go: forking, pull requests, and go-getting](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html)

----

# License
MIT

# Author
Teppei Fukuda
