# go-apk-version

![Test](https://github.com/knqyf263/go-apk-version/workflows/Test/badge.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/go-apk-version)](https://goreportcard.com/report/github.com/knqyf263/go-apk-version)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/knqyf263/go-apk-version/blob/master/LICENSE)

A Go library for parsing apk package versions

go-apk-version is a library for parsing and comparing versions

The implementation is based on [this implementation](https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/master/src/version.c)

OS: Alpine


# Installation and Usage

Installation can be done with a normal go get:

```
$ go get github.com/knqyf263/go-apk-version
```

## Version Parsing and Comparison

```
import "github.com/knqyf263/go-apk-version"

v1, err := version.NewVersion("1.2.3")
v2, err := version.NewVersion("1.2.3-r1")

// Comparison example. You can use GreaterThan and Equal as well.
if v1.LessThan(v2) {
    fmt.Printf("%s is less than %s", v1, v2)
}
```

## Version Sorting

```
raw := []string{"1.2.3", "1.2.3_alpha1", "1.2.3-r1", "1.2.4", "1.0_p9-r0"}
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

1. fork a repository: github.com/knqyf263/go-apk-version to github.com/you/repo
2. get original code: `go get github.com/knqyf263/go-apk-version`
3. work on original code
4. add remote to your repo: git remote add myfork https://github.com/you/repo.git
5. push your changes: git push myfork
6. create a new Pull Request

- see [GitHub and Go: forking, pull requests, and go-getting](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html)

----

# License
Apache License 2.0

# Author
Teppei Fukuda