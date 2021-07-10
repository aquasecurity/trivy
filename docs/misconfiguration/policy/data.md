# Custom Data

## Overview
Custom policies may require additional data in order to determine an answer.

For example, an allowed list of resources that can be created. Instead of hardcoding this information inside of your policy, Trivy allows passing paths to data files with the --data flag.

## Examples
[here](https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-data)
