#! /bin/bash
# fetch labels and their IDs
# requires authenticated gh cli, assumes repo but current git repository

gh api graphql -F repo="{repo}" -F owner="{owner}" -f query='
    query GetLabelIds($owner: String!, $repo: String!) {
    repository(name: $repo, owner: $owner) {
        id
        labels(first: 100) {
        nodes {
            id
            name
        }
        }
    }
    }'