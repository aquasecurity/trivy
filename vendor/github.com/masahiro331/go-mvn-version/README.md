# go-mvn-version

A Go library for parsing maven(java) package versions

go-mvn-version is a library for parsing and comparing versions

The implementation is based on [this specification](https://maven.apache.org/pom.html#Version_Order_Specification)

other reference: [maven implementation](https://github.com/apache/maven/blob/master/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java)


# Installation and Usage
Installation can be done with a normal go get:

```
$ go get github.com/masahiro331/go-mvn-version
```

# Version Parsing and Comparison
```
import "github.com/masahiro331/go-mvn-version"

v1, err := version.NewVersion("10-snapshot")
v2, err := version.NewVersion("10-b1")

if v1.GreaterThan(*v2) {
    fmt.Printf("%s is greater than %s", v1, v2)
}
```

# WARNING
This implementation based on the [maven specification](https://maven.apache.org/pom.html#Version_Order_Specification), but not the [maven implementation](https://github.com/apache/maven/blob/master/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java).

See issues: [ComparableVersion incorrectly parses certain version strings](https://issues.apache.org/jira/browse/MNG-6420)
```
$ go test .
--- FAIL: TestVersionsNumber (0.00s)
    version_test.go:415: expected: 2.0.a < 2.0.0.a
    version_test.go:418: expected: 2.0.0.a > 2.0.a
FAIL
FAIL    github.com/masahiro331/go-mvn-version/pkg/version       0.005s
FAIL
```

----

# License
Apache License 2.0

# Author
Masahiro Fujimura
