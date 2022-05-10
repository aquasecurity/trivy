# memoryfs

<img width="20%" align="right" src="https://i.giphy.com/media/SuEFqeWxlLcvm/giphy.webp" />

An in-memory filesystem implementation of io/fs.FS.

`memoryfs` implements all of the currently defined `io/fs` interfaces:

- [fs.FS](https://pkg.go.dev/io/fs#FS)
- [fs.GlobFS](https://pkg.go.dev/io/fs#GlobFS)
- [fs.ReadDirFS](https://pkg.go.dev/io/fs#ReadDirFS)
- [fs.ReadFileFS](https://pkg.go.dev/io/fs#ReadFileFS)
- [fs.StatFS](https://pkg.go.dev/io/fs#StatFS)
- [fs.SubFS](https://pkg.go.dev/io/fs#SubFS)

It also allows the creation of files and directories.

## Example

```go
package main

import (
    "fmt"
    "io/fs"

    "github.com/liamg/memoryfs"
)

func main() {

    memfs := memoryfs.New()

    if err := memfs.MkdirAll("my/dir", 0o700); err != nil {
        panic(err)
    }

    if err := memfs.WriteFile("my/dir/file.txt", []byte("hello world"), 0o600); err != nil {
        panic(err)
    }

    data, err := fs.ReadFile(memfs, "my/dir/file.txt")
    if err != nil {
        panic(err)
    }

    fmt.Println(string(data))
}
```

## Lazy Loading

If you are mirroring a disk file-system in memory, it can become very inefficient when large files are in use. For this scenario, the [WriteLazyFile](https://pkg.go.dev/github.com/liamg/memoryfs#FS.WriteLazyFile) method is recommended. It allows you to add a file whose content will be provided on-demand by calling the [LazyOpener](https://pkg.go.dev/github.com/liamg/memoryfs#LazyOpener) function.

