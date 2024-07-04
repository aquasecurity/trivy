#! /bin/bash
# add a label to a discussion
# requires authenticated gh cli, assumes repo but current git repository
# args:
#   $1: discussion ID (not number!), e.g DIC_kwDOE0GiPM4CXnDc, required
#   $2: label ID, e.g. MDU6TGFiZWwzNjIzNjY0MjQ=, required
discussion_id="$1"
label_id="$2"
gh api graphql -F labelableId="$discussion_id" -F labelId="$label_id" -F repo="{repo}" -F owner="{owner}" -f query='
        mutation AddLabels($labelId: ID!, $labelableId:ID!) {
            addLabelsToLabelable(
                input: {labelIds: [$labelId], labelableId: $labelableId}
            ) {
                clientMutationId
            }
        }'