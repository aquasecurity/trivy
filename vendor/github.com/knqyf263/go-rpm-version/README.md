# go-rpm-version

[![Build Status](https://travis-ci.org/knqyf263/go-rpm-version.svg?branch=master)](https://travis-ci.org/knqyf263/go-rpm-version)
[![Coverage Status](https://coveralls.io/repos/github/knqyf263/go-rpm-version/badge.svg?branch=master)](https://coveralls.io/github/knqyf263/go-rpm-version?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/go-rpm-version)](https://goreportcard.com/report/github.com/knqyf263/go-rpm-version)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/knqyf263/go-rpm-version/blob/master/LICENSE)

A Go library for parsing rpm package versions

go-rpm-version is a library for parsing and comparing rpm versions

For the original C implementation, see:
https://github.com/rpm-software-management/rpm/blob/master/lib/rpmvercmp.c#L16

OS: RedHat/CentOS

# Installation and Usage

Installation can be done with a normal go get:

```
$ go get github.com/knqyf263/go-rpm-version
```

## Version Parsing and Comparison

```
import "github.com/knqyf263/go-rpm-version"

v1, err := version.NewVersion("2:6.0-1")
v2, err := version.NewVersion("2:6.0-2.el6")

// Comparison example. There is also GreaterThan, Equal.
if v1.LessThan(v2) {
    fmt.Printf("%s is less than %s", v1, v2)
}
```

## Version Sorting

```
raw := []string{"5.3p1-112", "3.6.1p2-21.sel", "3.6.1p2-22", "5.3p1-105", "3.6.1p2-21"}
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

1. fork a repository: github.com/knqyf263/go-rpm-version to github.com/you/repo
2. get original code: `go get github.com/knqyf263/go-rpm-version`
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
