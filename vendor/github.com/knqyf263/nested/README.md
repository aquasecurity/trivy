# nested
Easier way to handle the nested data structure

[![GoDoc](https://godoc.org/github.com/knqyf263/nested?status.svg)](https://godoc.org/github.com/knqyf263/nested)
[![Build Status](https://travis-ci.org/knqyf263/nested.svg?branch=master)](https://travis-ci.org/knqyf263/nested)
[![Coverage Status](https://coveralls.io/repos/github/knqyf263/nested/badge.svg?branch=master)](https://coveralls.io/github/knqyf263/nested?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/nested)](https://goreportcard.com/report/github.com/knqyf263/nested)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/knqyf263/nested/blob/master/LICENSE)

## Usage

### Set/Get/Delete

```
package main

import (
	"fmt"

	"github.com/knqyf263/nested"
)

func main() {
	n := nested.Nested{}

	n.Set([]string{"a", "b"}, 1)
	n.SetByString("a.c.d", ".", "test")
	n.SetByString("/e/f", "/", true)

	var result interface{}
	result, _ = n.Get([]string{"a", "c", "d"})
	fmt.Println(result)
	// Output: test

	result, _ = n.GetByString("e/f", "/")
	fmt.Println(result)
	// Output: true

	var b int
	b, _ = n.GetInt([]string{"a", "b"})
	fmt.Println(b)
	// Output: 1
	
	n.Delete([]string{"a", "c"})
}
```

### Walk

```
func main() {
	n := nested.Nested{}
	n.Set([]string{"a", "b", "c"}, 1)
	n.Set([]string{"d", "e"}, 2)
	n.SetByString("f.g.h", ".", false)

	walkFn := func(keys []string, value interface{}) error {
		key := strings.Join(keys, ".")
		// Skip all keys under "f"
		if key == "f" {
			return nested.SkipKey
		}
		fmt.Println(key, value)
		return nil
	}
	n.Walk(walkFn)

	// Output:
	// a map[b:map[c:1]]
	// a.b map[c:1]
	// a.b.c 1
	// d map[e:2]
	// d.e 2
	// f map[g:map[h:1]]
}
```

## Install

```
$ go get github.com/knqyf263/nested
```

## Contribute

1. fork a repository: github.com/knqyf263/nested to github.com/you/repo
2. get original code: `go get github.com/knqyf263/nested`
3. work on original code
4. add remote to your repo: git remote add myfork https://github.com/you/repo.git
5. push your changes: git push myfork
6. create a new Pull Request

- see [GitHub and Go: forking, pull requests, and go-getting](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html)

----

## License
MIT

## Author
Teppei Fukuda