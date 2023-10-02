#!/bin/sh

tag=$1

# From https://docs.docker.com/engine/reference/commandline/tag/
# A tag name must be valid ASCII and may contain lowercase and uppercase letters, digits, underscores, periods and dashes.
# A tag name may not start with a period or a dash and may contain a maximum of 128 characters.

# remove invalid leading characters
tag=`echo ${tag} | sed 's/^[^a-zA-Z0-9_]*//'`

# remove other invalid characters
tag=`echo "${tag}" | sed -E 's/[^a-zA-Z0-9]+/-/g'`

echo $tag