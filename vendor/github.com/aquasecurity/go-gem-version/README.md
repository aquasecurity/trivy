# go-gem-version

![Test](https://github.com/aquasecurity/go-gem-version/workflows/Test/badge.svg?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/go-gem-version)](https://goreportcard.com/report/github.com/aquasecurity/go-gem-version)
![GitHub](https://img.shields.io/github/license/aquasecurity/go-gem-version)

go-gem-version is a library for parsing RubyGems versions and version constraints, and verifying versions against a set of constraints.
go-gem-version can sort a collection of versions properly, handles prerelease versions, etc.

Versions used with go-gem-version must follow [RubyGems versioning policy](https://guides.rubygems.org/patterns/).

For more details, see [version.rb](https://github.com/rubygems/rubygems/blob/6914b4ec439ae1e7079b3c08576cb3fbce68aa69/lib/rubygems/version.rb) and [requirement.rb](https://github.com/rubygems/rubygems/blob/6914b4ec439ae1e7079b3c08576cb3fbce68aa69/lib/rubygems/requirement.rb).

## Usage
### Version Parsing and Comparison

See [example](./examples/comparison/main.go)

```
v1, _ := gem.NewVersion("1.2.a")
v2, _ := gem.NewVersion("1.2")

// Comparison example. There is also GreaterThan, Equal, and just
// a simple Compare that returns an int allowing easy >=, <=, etc.
if v1.LessThan(v2) {
	fmt.Printf("%s is less than %s", v1, v2)
}
```

### Version Constraints
See [example](./examples/constraint/main.go)

```
v, _ := gem.NewVersion("2.1")
c, _ := gem.NewConstraints(">= 1.0, < 1.4 || > 2.0")

if c.Check(v) {
	fmt.Printf("%s satisfies constraints '%s'", v, c)
}
```

### Version Sorting
See [example](./examples/sort/main.go)

```
versionsRaw := []string{"1.1", "0.7.1", "1.4.a", "1.4.a.1", "1.4", "1.4.0.1"}
versions := make([]gem.Version, len(versionsRaw))
for i, raw := range versionsRaw {
	v, _ := gem.NewVersion(raw)
	versions[i] = v
}

// After this, the versions are properly sorted
sort.Sort(gem.Collection(versions))
```

## Pessimistic Operator
- `~> 3.0` := `>= 3.0, < 4.0`
- `~> 3.0.0` := `>= 3.0.0, < 3.1`
- `~> 3.5` := `>= 3.5, < 4.0`
- `~> 3.5.0` := `>= 3.5.0, < 3.6`
- `~> 3` := `>= 3.0, < 4.0`

For more details, see [here](https://thoughtbot.com/blog/rubys-pessimistic-operator)
