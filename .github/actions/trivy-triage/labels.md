The configuration file expects a label reference by it's GitHub "Global ID".
To find the IDs of labels in a repository run the following:

```console
gh api graphql -f owner=aquasecurity -f repo=trivy -f query='query GetLabelIds($owner:String!, $repo:String!) {
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
```
