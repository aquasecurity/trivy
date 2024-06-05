#! /bin/bash
# fetch discussion by discussion number
# requires authenticated gh cli, assumes repo but current git repository
# args:
#   $1: discussion number, e.g 123, required

discussion_num="$1"
gh api graphql -F discussion_num="$discussion_num" -F repo="{repo}" -F owner="{owner}" -f query='
    query Discussion ($owner: String!, $repo: String!, $discussion_num: Int!){
    repository(name: $repo, owner: $owner) {
        discussion(number: $discussion_num) {
        number,
        id,
        body,
        category {
            id,
            name
        },
        labels(first: 100) {
            edges {
            node {
                id,
                name
            }
            }
        }
        }
    }
    }'