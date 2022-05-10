# walker

[![](https://godoc.org/github.com/saracen/walker?status.svg)](http://godoc.org/github.com/saracen/walker)

`walker` is a faster, parallel version, of `filepath.Walk`.

```go
// walk function called for every path found
walkFn := func(pathname string, fi os.FileInfo) error {
    fmt.Printf("%s: %d bytes\n", pathname, fi.Size())
    return nil
}

// error function called for every error encountered
errorCallbackOption := walker.WithErrorCallback(func(pathname string, err error) error {
    // ignore permissione errors
    if os.IsPermission(err) {
        return nil
    }
    // halt traversal on any other error
    return err
})

walker.Walk("/tmp", walkFn, errorCallbackOption)
```

## Benchmarks

- Standard library (`filepath.Walk`) is `FilepathWalk`.
- This library is `WalkerWalk`
- `FastwalkWalk` is [fastwalk](https://github.com/golang/tools/tree/master/internal/fastwalk).
- `GodirwalkWalk` is [godirwalk](https://github.com/karrick/godirwalk).

This library and `filepath.Walk` both perform `os.Lstat` calls and provide a full `os.FileInfo` structure to the callback. `BenchmarkFastwalkWalkLstat` and `BenchmarkGodirwalkWalkLstat` include this stat call for better comparison with `BenchmarkFilepathWalk` and `BenchmarkWalkerWalk`.

This library and `fastwalk` both require the callback to be safe for concurrent use. `BenchmarkFilepathWalkAppend`, `BenchmarkWalkerWalkAppend`, `BenchmarkFastwalkWalkAppend` and `BenchmarkGodirwalkWalkAppend` append the paths found to a string slice. The callback, for the libraries that require it, use a mutex, for better comparison with the libraries that require no locking.

This library will not always be the best/fastest option. In general, if you're on Windows, or performing `lstat` calls, it does a pretty decent job. If you're not, I've found `fastwalk` to perform better on machines with fewer cores.

These benchmarks were performed with a warm cache.

```
goos: linux
goarch: amd64
pkg: github.com/saracen/walker
BenchmarkFilepathWalk-16                       1        1437919955 ns/op        340100304 B/op    775525 allocs/op
BenchmarkFilepathWalkAppend-16                 1        1226169600 ns/op        351722832 B/op    775556 allocs/op
BenchmarkWalkerWalk-16                         8         133364860 ns/op        92611308 B/op     734674 allocs/op
BenchmarkWalkerWalkAppend-16                   7         166917499 ns/op        104231474 B/op    734693 allocs/op
BenchmarkFastwalkWalk-16                       6         241763690 ns/op        25257176 B/op     309423 allocs/op
BenchmarkFastwalkWalkAppend-16                 4         285673715 ns/op        36898800 B/op     309456 allocs/op
BenchmarkFastwalkWalkLstat-16                  6         176641625 ns/op        73769765 B/op     592980 allocs/op
BenchmarkGodirwalkWalk-16                      2         714625929 ns/op        145340576 B/op    723225 allocs/op
BenchmarkGodirwalkWalkAppend-16                2         597653802 ns/op        156963288 B/op    723256 allocs/op
BenchmarkGodirwalkWalkLstat-16                 1        1186956102 ns/op        193724464 B/op   1006727 allocs/op
```

```
goos: windows
goarch: amd64
pkg: github.com/saracen/walker
BenchmarkFilepathWalk-16                       1        1268606000 ns/op        101248040 B/op    650718 allocs/op
BenchmarkFilepathWalkAppend-16                 1        1276617400 ns/op        107079288 B/op    650744 allocs/op
BenchmarkWalkerWalk-16                        12          98901983 ns/op        52393125 B/op     382836 allocs/op
BenchmarkWalkerWalkAppend-16                  12          99733117 ns/op        58220869 B/op     382853 allocs/op
BenchmarkFastwalkWalk-16                      10         109107980 ns/op        53032702 B/op     401320 allocs/op
BenchmarkFastwalkWalkAppend-16                10         107512330 ns/op        58853827 B/op     401336 allocs/op
BenchmarkFastwalkWalkLstat-16                  3         379318333 ns/op        100606232 B/op    653931 allocs/op
BenchmarkGodirwalkWalk-16                      3         466418533 ns/op        42955197 B/op     579974 allocs/op
BenchmarkGodirwalkWalkAppend-16                3         476391833 ns/op        48786530 B/op     580002 allocs/op
BenchmarkGodirwalkWalkLstat-16                 1        1250652800 ns/op        90536184 B/op     832562 allocs/op
```

Performing benchmarks without having the OS cache the directory information isn't straight forward, but to get a sense of the performance, we can flush the cache and roughly time how long it took to walk a directory:

#### filepath.Walk
```
$ sudo su -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; go test -run TestFilepathWalkDir -benchdir $GOPATH
ok      github.com/saracen/walker       3.846s
```

#### walker
```
$ sudo su -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; go test -run TestWalkerWalkDir -benchdir $GOPATH
ok      github.com/saracen/walker       0.353s
```

#### fastwalk
```
$ sudo su -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; go test -run TestFastwalkWalkDir -benchdir $GOPATH
ok      github.com/saracen/walker       0.306s
```

#### fastwalk (lstat)
```
$ sudo su -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; go test -run TestFastwalkWalkLstatDir -benchdir $GOPATH
ok      github.com/saracen/walker       0.339s
```

#### godirwalk
```
$ sudo su -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; go test -run TestGodirwalkWalkDir -benchdir $GOPATH
ok      github.com/saracen/walker       3.208s
```
