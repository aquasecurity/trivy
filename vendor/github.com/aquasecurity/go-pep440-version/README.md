# go-pep440-version
![Test](https://github.com/aquasecurity/go-pep440-version/workflows/Test/badge.svg?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/go-pep440-version)](https://goreportcard.com/report/github.com/aquasecurity/go-pep440-version)
![GitHub](https://img.shields.io/github/license/aquasecurity/go-pep440-version)

A golang library for parsing PEP 440 compliant Python versions

go-pep440-version is a library for parsing versions of Python software distributions and version specifiers, and verifying versions against a set of specifiers.

Versions used with go-pep440-version must follow [PEP 440](https://www.python.org/dev/peps/pep-0440/).

For more details, see [pypa/packaging](https://github.com/pypa/packaging)

## Usage
### Version Parsing and Comparison

See [example](./examples/comparison/main.go)

```
v1, _ := version.Parse("1.2.a")
v2, _ := version.Parse("1.2")

// Comparison example. There is also GreaterThan, Equal, and just
// a simple Compare that returns an int allowing easy >=, <=, etc.
if v1.LessThan(v2) {
	fmt.Printf("%s is less than %s", v1, v2)
}
```

### Version Constraints
See [example](./examples/constraint/main.go)

```
v, _ := version.Parse("2.1")
c, _ := version.NewSpecifiers(">= 1.0, < 1.4 || > 2.0")

if c.Check(v) {
	fmt.Printf("%s satisfies specifiers '%s'", v, c)
}
```

## Status

- [x] `>`
- [x] `>=`
- [x] `<`
- [x] `<=`
- [x] `==`
- [x] `!=`
- [x] `~=`
- [ ] `===`