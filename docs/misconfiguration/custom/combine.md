# Combined input

## Overview
Trivy usually scans each configuration file individually. 
Sometimes it might be useful to compare values from different configuration files simultaneously.

When `combine` is set to true, all config files under the specified directory are combined into one input data structure.

!!! example
    ```
    __rego_input__ := {
        "combine": false,
    }
    ```

In "combine" mode, the `input` document becomes an array, where each element is an object with two fields:

- `"path": "path/to/file"`: the relative file path of the respective file
- `"contents": ...`: the parsed content of the respective file

Now you can ensure that duplicate values match across the entirety of your configuration files.

## Return value
In "combine" mode, the `deny` entrypoint must return an object with two keys

`filepath` (required)
: the relative file path of the file being evaluated

`msg` (required)
: the message describing an issue

!!! example
    ```
    deny[res] {
        resource := input[i].contents
        ... some logic ...

    	res := {
    		"filepath": input[i].path,
    		"msg": "something bad",
    	}
    }
    ```

