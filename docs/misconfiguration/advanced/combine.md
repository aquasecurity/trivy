# Combined input

## Overview
You might want to compare multiple values from different configurations simultaneously.
When `combine` is set to true, all config files under the specified directory are combined into one input data structure.

!!! example
    ```
    __rego_input__ := {
        "combine": false,
    }
    ```

The structure is an array where each element is a map with two keys: a path key with the relative file path of the file being evaluated and a contents key containing the actual document.
Now you can ensure that duplicate values match across the entirety of your configuration files.

## Return value
The `deny` entrypoint must return an object with two keys

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