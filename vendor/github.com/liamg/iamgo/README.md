# iamgo

`iamgo` is a Go package for parsing/assembling AWS IAM policy documents, as the official SDK does not seem to fully support this.

It handles the multiple possible types for various IAM elements and hides this complexity from the consumer.

## Example

```go
package main

import (
    "fmt"
    
    "github.com/liamg/iamgo"
)

func main() {

    rawJSON := []byte(`...`)

    doc, err := iamgo.Parse(rawJSON)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Done: %#v\n", doc)
}
```
